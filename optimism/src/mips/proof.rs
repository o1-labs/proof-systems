use crate::DOMAIN_SIZE;
use ark_ff::Zero;
use ark_poly::{univariate::DensePolynomial, Evaluations, Polynomial, Radix2EvaluationDomain as D};
use kimchi::circuits::domains::EvaluationDomains;
use kimchi::plonk_sponge::FrSponge;
use kimchi::{curve::KimchiCurve, groupmap::GroupMap};
use mina_poseidon::sponge::ScalarChallenge;
use mina_poseidon::FqSponge;
use poly_commitment::{
    commitment::{
        absorb_commitment, combined_inner_product, BatchEvaluationProof, Evaluation, PolyComm,
    },
    evaluation_proof::DensePolynomialOrEvaluations,
    OpenProof, SRS as _,
};
use rand::thread_rng;
use rayon::iter::{
    FromParallelIterator, IndexedParallelIterator, IntoParallelIterator, IntoParallelRefIterator,
    IntoParallelRefMutIterator, ParallelIterator,
};

#[derive(Debug)]
pub struct WitnessColumns<G> {
    pub scratch: [G; crate::mips::witness::SCRATCH_SIZE],
    pub instruction_counter: G,
    pub error: G,
}

impl<G> IntoParallelIterator for WitnessColumns<G>
where
    Vec<G>: IntoParallelIterator,
{
    type Iter = <Vec<G> as IntoParallelIterator>::Iter;
    type Item = <Vec<G> as IntoParallelIterator>::Item;

    fn into_par_iter(self) -> Self::Iter {
        let mut iter_contents = Vec::with_capacity(crate::mips::witness::SCRATCH_SIZE + 2);
        iter_contents.extend(self.scratch);
        iter_contents.push(self.instruction_counter);
        iter_contents.push(self.error);
        iter_contents.into_par_iter()
    }
}

impl<G: Send + std::fmt::Debug> FromParallelIterator<G> for WitnessColumns<G> {
    fn from_par_iter<I>(par_iter: I) -> Self
    where
        I: IntoParallelIterator<Item = G>,
    {
        let mut iter_contents = par_iter.into_par_iter().collect::<Vec<_>>();
        let error = iter_contents.pop().unwrap();
        let instruction_counter = iter_contents.pop().unwrap();
        WitnessColumns {
            scratch: iter_contents.try_into().unwrap(),
            instruction_counter,
            error,
        }
    }
}

impl<'data, G> IntoParallelIterator for &'data WitnessColumns<G>
where
    Vec<&'data G>: IntoParallelIterator,
{
    type Iter = <Vec<&'data G> as IntoParallelIterator>::Iter;
    type Item = <Vec<&'data G> as IntoParallelIterator>::Item;

    fn into_par_iter(self) -> Self::Iter {
        let mut iter_contents = Vec::with_capacity(crate::mips::witness::SCRATCH_SIZE + 2);
        iter_contents.extend(self.scratch.iter());
        iter_contents.push(&self.instruction_counter);
        iter_contents.push(&self.error);
        iter_contents.into_par_iter()
    }
}

impl<'data, G> IntoParallelIterator for &'data mut WitnessColumns<G>
where
    Vec<&'data mut G>: IntoParallelIterator,
{
    type Iter = <Vec<&'data mut G> as IntoParallelIterator>::Iter;
    type Item = <Vec<&'data mut G> as IntoParallelIterator>::Item;

    fn into_par_iter(self) -> Self::Iter {
        let mut iter_contents = Vec::with_capacity(crate::mips::witness::SCRATCH_SIZE + 2);
        iter_contents.extend(self.scratch.iter_mut());
        iter_contents.push(&mut self.instruction_counter);
        iter_contents.push(&mut self.error);
        iter_contents.into_par_iter()
    }
}

#[derive(Debug)]
pub struct ProofInputs<G: KimchiCurve> {
    evaluations: WitnessColumns<Vec<G::ScalarField>>,
}

impl<G: KimchiCurve> Default for ProofInputs<G> {
    fn default() -> Self {
        ProofInputs {
            evaluations: WitnessColumns {
                scratch: std::array::from_fn(|_| {
                    (0..DOMAIN_SIZE).map(|_| G::ScalarField::zero()).collect()
                }),
                instruction_counter: (0..DOMAIN_SIZE).map(|_| G::ScalarField::zero()).collect(),
                error: (0..DOMAIN_SIZE).map(|_| G::ScalarField::zero()).collect(),
            },
        }
    }
}

#[derive(Debug)]
pub struct Proof<G: KimchiCurve, OpeningProof: OpenProof<G>> {
    commitments: WitnessColumns<PolyComm<G>>,
    zeta_evaluations: WitnessColumns<G::ScalarField>,
    zeta_omega_evaluations: WitnessColumns<G::ScalarField>,
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
    inputs: &WitnessColumns<Vec<G::ScalarField>>,
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
            .collect::<WitnessColumns<_>>()
    };
    let mut fq_sponge = EFqSponge::new(G::other_curve_sponge_params());
    for comm in commitments.scratch.iter() {
        absorb_commitment(&mut fq_sponge, comm)
    }
    absorb_commitment(&mut fq_sponge, &commitments.instruction_counter);
    absorb_commitment(&mut fq_sponge, &commitments.error);
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
        let WitnessColumns {
            scratch,
            instruction_counter,
            error,
        } = evaluations;
        let eval_col = |evals: Vec<G::ScalarField>| {
            Evaluations::<G::ScalarField, D<G::ScalarField>>::from_vec_and_domain(evals, domain.d1)
                .interpolate()
        };
        let scratch = scratch.into_par_iter().map(eval_col).collect::<Vec<_>>();
        WitnessColumns {
            scratch: scratch.try_into().unwrap(),
            instruction_counter: eval_col(instruction_counter),
            error: eval_col(error),
        }
    };
    let commitments = {
        let WitnessColumns {
            scratch,
            instruction_counter,
            error,
        } = &polys;
        let comm = |poly: &DensePolynomial<G::ScalarField>| srs.commit_non_hiding(poly, 1, None);
        let scratch = scratch.par_iter().map(comm).collect::<Vec<_>>();
        WitnessColumns {
            scratch: scratch.try_into().unwrap(),
            instruction_counter: comm(instruction_counter),
            error: comm(error),
        }
    };

    let mut fq_sponge = EFqSponge::new(G::other_curve_sponge_params());
    for comm in commitments.scratch.iter() {
        absorb_commitment(&mut fq_sponge, comm)
    }
    absorb_commitment(&mut fq_sponge, &commitments.instruction_counter);
    absorb_commitment(&mut fq_sponge, &commitments.error);
    let zeta_chal = ScalarChallenge(fq_sponge.challenge());
    let (_, endo_r) = G::endos();
    let zeta = zeta_chal.to_field(endo_r);
    let omega = domain.d1.group_gen;
    let zeta_omega = zeta * omega;

    let evals = |point| {
        let WitnessColumns {
            scratch,
            instruction_counter,
            error,
        } = &polys;
        let comm = |poly: &DensePolynomial<G::ScalarField>| poly.evaluate(point);
        let scratch = scratch.par_iter().map(comm).collect::<Vec<_>>();
        WitnessColumns {
            scratch: scratch.try_into().unwrap(),
            instruction_counter: comm(instruction_counter),
            error: comm(error),
        }
    };
    let zeta_evaluations = evals(&zeta);
    let zeta_omega_evaluations = evals(&zeta_omega);
    let group_map = G::Map::setup();
    let mut polynomials: Vec<_> = polys.scratch.into_iter().collect();
    polynomials.push(polys.instruction_counter);
    polynomials.push(polys.error);
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
        .scratch
        .iter()
        .zip(zeta_omega_evaluations.scratch.iter())
    {
        fr_sponge.absorb(zeta_eval);
        fr_sponge.absorb(zeta_omega_eval);
    }
    fr_sponge.absorb(&zeta_evaluations.instruction_counter);
    fr_sponge.absorb(&zeta_omega_evaluations.instruction_counter);
    fr_sponge.absorb(&zeta_evaluations.error);
    fr_sponge.absorb(&zeta_omega_evaluations.error);

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
    for comm in commitments.scratch.iter() {
        absorb_commitment(&mut fq_sponge, comm)
    }
    absorb_commitment(&mut fq_sponge, &commitments.instruction_counter);
    absorb_commitment(&mut fq_sponge, &commitments.error);
    let zeta_chal = ScalarChallenge(fq_sponge.challenge());
    let (_, endo_r) = G::endos();
    let zeta: G::ScalarField = zeta_chal.to_field(endo_r);
    let omega = domain.d1.group_gen;
    let zeta_omega = zeta * omega;

    let fq_sponge_before_evaluations = fq_sponge.clone();
    let mut fr_sponge = EFrSponge::new(G::sponge_params());
    fr_sponge.absorb(&fq_sponge.digest());

    let mut es: Vec<_> = zeta_evaluations
        .scratch
        .iter()
        .zip(zeta_omega_evaluations.scratch.iter())
        .map(|(zeta, zeta_omega)| (vec![vec![*zeta], vec![*zeta_omega]], None))
        .collect();
    es.push((
        vec![
            vec![zeta_evaluations.instruction_counter],
            vec![zeta_omega_evaluations.instruction_counter],
        ],
        None,
    ));
    es.push((
        vec![
            vec![zeta_evaluations.error],
            vec![zeta_omega_evaluations.error],
        ],
        None,
    ));

    let mut evaluations: Vec<_> = commitments
        .scratch
        .iter()
        .zip(
            zeta_evaluations
                .scratch
                .iter()
                .zip(zeta_omega_evaluations.scratch.iter()),
        )
        .map(|(commitment, (zeta_eval, zeta_omega_eval))| Evaluation {
            commitment: commitment.clone(),
            evaluations: vec![vec![*zeta_eval], vec![*zeta_omega_eval]],
            degree_bound: None,
        })
        .collect();
    evaluations.push(Evaluation {
        commitment: commitments.instruction_counter.clone(),
        evaluations: vec![
            vec![zeta_evaluations.instruction_counter],
            vec![zeta_omega_evaluations.instruction_counter],
        ],
        degree_bound: None,
    });
    evaluations.push(Evaluation {
        commitment: commitments.error.clone(),
        evaluations: vec![
            vec![zeta_evaluations.error],
            vec![zeta_omega_evaluations.error],
        ],
        degree_bound: None,
    });

    for (zeta_eval, zeta_omega_eval) in zeta_evaluations
        .scratch
        .iter()
        .zip(zeta_omega_evaluations.scratch.iter())
    {
        fr_sponge.absorb(zeta_eval);
        fr_sponge.absorb(zeta_omega_eval);
    }
    fr_sponge.absorb(&zeta_evaluations.instruction_counter);
    fr_sponge.absorb(&zeta_omega_evaluations.instruction_counter);
    fr_sponge.absorb(&zeta_evaluations.error);
    fr_sponge.absorb(&zeta_omega_evaluations.error);

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
    type SpongeParams = PlonkSpongeConstantsKimchi;
    type BaseSponge = DefaultFqSponge<ark_bn254::g1::Config, SpongeParams>;
    type ScalarSponge = DefaultFrSponge<Fp, SpongeParams>;
    type BN254Config = ark_ec::bn::Bn<ark_bn254::Config>;
    type OpeningProof = PairingProof<BN254Config>;

    let rng = &mut rand::rngs::OsRng;

    let domain_size = 1 << 15;

    let proof_inputs = {
        let scratch =
            std::array::from_fn(|_| (0..domain_size).map(|_| Fp::rand(rng)).collect::<Vec<_>>());
        let instruction_counter = (0..domain_size).map(|_| Fp::rand(rng)).collect::<Vec<_>>();
        let error = (0..domain_size).map(|_| Fp::rand(rng)).collect::<Vec<_>>();
        ProofInputs {
            evaluations: WitnessColumns {
                scratch,
                instruction_counter,
                error,
            },
        }
    };
    let domain = EvaluationDomains::<Fp>::create(domain_size).unwrap();

    // Trusted setup toxic waste
    let x = Fp::rand(rng);

    let mut srs = PairingSRS::create(x, domain_size);
    srs.full_srs.add_lagrange_basis(domain.d1);

    let proof = prove::<_, OpeningProof, BaseSponge, ScalarSponge>(domain, &srs, proof_inputs);

    assert!(verify::<_, OpeningProof, BaseSponge, ScalarSponge>(
        domain, &srs, &proof
    ));
}
