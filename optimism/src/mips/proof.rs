use crate::{mips::column::MIPSWitness, DOMAIN_SIZE};
use ark_ff::Zero;
use ark_poly::{univariate::DensePolynomial, Evaluations, Polynomial, Radix2EvaluationDomain as D};
use kimchi::{
    circuits::domains::EvaluationDomains, curve::KimchiCurve, groupmap::GroupMap,
    plonk_sponge::FrSponge,
};
use mina_poseidon::{sponge::ScalarChallenge, FqSponge};
use poly_commitment::{
    commitment::{
        absorb_commitment, combined_inner_product, BatchEvaluationProof, Evaluation, PolyComm,
    },
    evaluation_proof::DensePolynomialOrEvaluations,
    OpenProof, SRS as _,
};
use rand::thread_rng;
use rayon::iter::{
    IndexedParallelIterator, IntoParallelIterator, IntoParallelRefIterator,
    IntoParallelRefMutIterator, ParallelIterator,
};

/// This structure contains the execution trace (or in other terms, the inputs
/// to construct the SNARK proof, explaining the structure name) as evaluations
/// of polynomials. It will be used by the prover as an input of the function
/// `prove` to build the commitments and evaluations of the polynomials.
#[derive(Debug)]
pub struct ProofInputs<G: KimchiCurve> {
    evaluations: MIPSWitness<Vec<G::ScalarField>>,
}

impl<G: KimchiCurve> Default for ProofInputs<G> {
    fn default() -> Self {
        ProofInputs {
            evaluations: MIPSWitness {
                cols: std::array::from_fn(|_| {
                    (0..DOMAIN_SIZE).map(|_| G::ScalarField::zero()).collect()
                }),
            },
        }
    }
}

#[derive(Debug)]
pub struct Proof<G: KimchiCurve, OpeningProof: OpenProof<G>> {
    commitments: MIPSWitness<PolyComm<G>>,
    zeta_evaluations: MIPSWitness<G::ScalarField>,
    zeta_omega_evaluations: MIPSWitness<G::ScalarField>,
    opening_proof: OpeningProof,
}

pub fn fold<
    G: KimchiCurve,
    OpeningProof: OpenProof<G>,
    EFqSponge: Clone + FqSponge<G::BaseField, G, G::ScalarField>,
    EFrSponge: FrSponge<G::ScalarField>,
>(
    domain: EvaluationDomains<G::ScalarField>,
    srs: &OpeningProof::SRS,
    accumulator: &mut ProofInputs<G>,
    inputs: &MIPSWitness<Vec<G::ScalarField>>,
) where
    <OpeningProof as poly_commitment::OpenProof<G>>::SRS: std::marker::Sync,
{
    let commitments = {
        inputs
            .par_iter()
            .map(|evals: &Vec<G::ScalarField>| {
                let evals = Evaluations::<G::ScalarField, D<G::ScalarField>>::from_vec_and_domain(
                    evals.clone(),
                    domain.d1,
                );
                srs.commit_evaluations_non_hiding(domain.d1, &evals)
            })
            .collect::<MIPSWitness<_>>()
    };
    let mut fq_sponge = EFqSponge::new(G::other_curve_sponge_params());
    for comm in commitments.cols.iter() {
        absorb_commitment(&mut fq_sponge, comm)
    }
    let scaling_challenge = ScalarChallenge(fq_sponge.challenge());
    let (_, endo_r) = G::endos();
    let scaling_challenge = scaling_challenge.to_field(endo_r);
    accumulator
        .evaluations
        .par_iter_mut()
        .zip(inputs.par_iter())
        .for_each(|(accumulator, inputs)| {
            accumulator
                .par_iter_mut()
                .zip(inputs.par_iter())
                .for_each(|(accumulator, input)| {
                    *accumulator = *input + scaling_challenge * *accumulator
                });
        });
}

pub fn prove<
    G: KimchiCurve,
    OpeningProof: OpenProof<G>,
    EFqSponge: Clone + FqSponge<G::BaseField, G, G::ScalarField>,
    EFrSponge: FrSponge<G::ScalarField>,
>(
    domain: EvaluationDomains<G::ScalarField>,
    srs: &OpeningProof::SRS,
    inputs: ProofInputs<G>,
) -> Proof<G, OpeningProof>
where
    OpeningProof::SRS: Sync,
{
    let ProofInputs { evaluations } = inputs;
    let polys = {
        let MIPSWitness { cols } = evaluations;
        let eval_col = |evals: Vec<G::ScalarField>| {
            Evaluations::<G::ScalarField, D<G::ScalarField>>::from_vec_and_domain(evals, domain.d1)
                .interpolate()
        };
        let cols = cols.into_par_iter().map(eval_col).collect::<Vec<_>>();
        MIPSWitness {
            cols: cols.try_into().unwrap(),
        }
    };
    let commitments = {
        let MIPSWitness { cols } = &polys;
        let comm = |poly: &DensePolynomial<G::ScalarField>| srs.commit_non_hiding(poly, 1, None);
        let cols = cols.par_iter().map(comm).collect::<Vec<_>>();
        MIPSWitness {
            cols: cols.try_into().unwrap(),
        }
    };

    let mut fq_sponge = EFqSponge::new(G::other_curve_sponge_params());
    for comm in commitments.cols.iter() {
        absorb_commitment(&mut fq_sponge, comm)
    }
    let zeta_chal = ScalarChallenge(fq_sponge.challenge());
    let (_, endo_r) = G::endos();
    let zeta = zeta_chal.to_field(endo_r);
    let omega = domain.d1.group_gen;
    let zeta_omega = zeta * omega;

    let evals = |point| {
        let MIPSWitness { cols } = &polys;
        let comm = |poly: &DensePolynomial<G::ScalarField>| poly.evaluate(point);
        let cols = cols.par_iter().map(comm).collect::<Vec<_>>();
        MIPSWitness {
            cols: cols.try_into().unwrap(),
        }
    };
    let zeta_evaluations = evals(&zeta);
    let zeta_omega_evaluations = evals(&zeta_omega);
    let group_map = G::Map::setup();
    let polynomials: Vec<_> = polys.cols.into_iter().collect();
    let polynomials: Vec<_> = polynomials
        .iter()
        .map(|poly| {
            (
                DensePolynomialOrEvaluations::DensePolynomial(poly),
                None,
                PolyComm {
                    unshifted: vec![G::ScalarField::zero()],
                    shifted: None,
                },
            )
        })
        .collect();
    let fq_sponge_before_evaluations = fq_sponge.clone();
    let mut fr_sponge = EFrSponge::new(G::sponge_params());
    fr_sponge.absorb(&fq_sponge.digest());

    for (zeta_eval, zeta_omega_eval) in zeta_evaluations
        .cols
        .iter()
        .zip(zeta_omega_evaluations.cols.iter())
    {
        fr_sponge.absorb(zeta_eval);
        fr_sponge.absorb(zeta_omega_eval);
    }

    let v_chal = fr_sponge.challenge();
    let v = v_chal.to_field(endo_r);
    let u_chal = fr_sponge.challenge();
    let u = u_chal.to_field(endo_r);

    let opening_proof = OpenProof::open::<_, _, D<G::ScalarField>>(
        srs,
        &group_map,
        polynomials.as_slice(),
        &[zeta, zeta_omega],
        v,
        u,
        fq_sponge_before_evaluations,
        &mut rand::rngs::OsRng,
    );

    Proof {
        commitments,
        zeta_evaluations,
        zeta_omega_evaluations,
        opening_proof,
    }
}

pub fn verify<
    G: KimchiCurve,
    OpeningProof: OpenProof<G>,
    EFqSponge: Clone + FqSponge<G::BaseField, G, G::ScalarField>,
    EFrSponge: FrSponge<G::ScalarField>,
>(
    domain: EvaluationDomains<G::ScalarField>,
    srs: &OpeningProof::SRS,
    proof: &Proof<G, OpeningProof>,
) -> bool {
    let Proof {
        commitments,
        zeta_evaluations,
        zeta_omega_evaluations,
        opening_proof,
    } = proof;

    let mut fq_sponge = EFqSponge::new(G::other_curve_sponge_params());
    for comm in commitments.cols.iter() {
        absorb_commitment(&mut fq_sponge, comm)
    }
    let zeta_chal = ScalarChallenge(fq_sponge.challenge());
    let (_, endo_r) = G::endos();
    let zeta: G::ScalarField = zeta_chal.to_field(endo_r);
    let omega = domain.d1.group_gen;
    let zeta_omega = zeta * omega;

    let fq_sponge_before_evaluations = fq_sponge.clone();
    let mut fr_sponge = EFrSponge::new(G::sponge_params());
    fr_sponge.absorb(&fq_sponge.digest());

    let es: Vec<_> = zeta_evaluations
        .cols
        .iter()
        .zip(zeta_omega_evaluations.cols.iter())
        .map(|(zeta, zeta_omega)| (vec![vec![*zeta], vec![*zeta_omega]], None))
        .collect();

    let evaluations: Vec<_> = commitments
        .cols
        .iter()
        .zip(
            zeta_evaluations
                .cols
                .iter()
                .zip(zeta_omega_evaluations.cols.iter()),
        )
        .map(|(commitment, (zeta_eval, zeta_omega_eval))| Evaluation {
            commitment: commitment.clone(),
            evaluations: vec![vec![*zeta_eval], vec![*zeta_omega_eval]],
            degree_bound: None,
        })
        .collect();

    for (zeta_eval, zeta_omega_eval) in zeta_evaluations
        .cols
        .iter()
        .zip(zeta_omega_evaluations.cols.iter())
    {
        fr_sponge.absorb(zeta_eval);
        fr_sponge.absorb(zeta_omega_eval);
    }

    let v_chal = fr_sponge.challenge();
    let v = v_chal.to_field(endo_r);
    let u_chal = fr_sponge.challenge();
    let u = u_chal.to_field(endo_r);

    let combined_inner_product =
        combined_inner_product(&[zeta, zeta_omega], &v, &u, es.as_slice(), DOMAIN_SIZE);

    let batch = BatchEvaluationProof {
        sponge: fq_sponge_before_evaluations,
        evaluations,
        evaluation_points: vec![zeta, zeta_omega],
        polyscale: v,
        evalscale: u,
        opening: opening_proof,
        combined_inner_product,
    };

    let group_map = G::Map::setup();
    OpeningProof::verify(srs, &group_map, &mut [batch], &mut thread_rng())
}

#[test]
fn test_mips_prover() {
    use ark_ff::UniformRand;
    use mina_poseidon::{
        constants::PlonkSpongeConstantsKimchi,
        sponge::{DefaultFqSponge, DefaultFrSponge},
    };
    use poly_commitment::pairing_proof::{PairingProof, PairingSRS};

    type Fp = ark_bn254::Fr;
    type BN254Parameters = ark_ec::bn::Bn<ark_bn254::Parameters>;
    type SpongeParams = PlonkSpongeConstantsKimchi;
    type BaseSponge = DefaultFqSponge<ark_bn254::g1::Parameters, SpongeParams>;
    type ScalarSponge = DefaultFrSponge<Fp, SpongeParams>;

    let rng = &mut rand::rngs::OsRng;

    let domain_size = 1 << 15;

    let proof_inputs = {
        let cols =
            std::array::from_fn(|_| (0..domain_size).map(|_| Fp::rand(rng)).collect::<Vec<_>>());
        ProofInputs {
            evaluations: MIPSWitness { cols },
        }
    };
    let domain = EvaluationDomains::<Fp>::create(domain_size).unwrap();

    // Trusted setup toxic waste
    let x = Fp::rand(rng);

    let mut srs = PairingSRS::create(x, domain_size);
    srs.full_srs.add_lagrange_basis(domain.d1);

    let proof = prove::<_, PairingProof<BN254Parameters>, BaseSponge, ScalarSponge>(
        domain,
        &srs,
        proof_inputs,
    );

    assert!(verify::<
        _,
        PairingProof<BN254Parameters>,
        BaseSponge,
        ScalarSponge,
    >(domain, &srs, &proof));
}
