use crate::{witness::Witness, DOMAIN_SIZE};
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

/// This struct contains the evaluations of the Witness columns across the whole
/// domain of the circuit
#[derive(Debug)]
pub struct ProofInputs<const N: usize, G: KimchiCurve> {
    evaluations: Witness<N, Vec<G::ScalarField>>,
}

impl<const N: usize, G: KimchiCurve> Default for ProofInputs<N, G> {
    fn default() -> Self {
        ProofInputs {
            evaluations: Witness {
                cols: std::array::from_fn(|_| {
                    (0..DOMAIN_SIZE).map(|_| G::ScalarField::zero()).collect()
                }),
            },
        }
    }
}

/// This struct contains the proof of the Keccak circuit
#[derive(Debug)]
pub struct Proof<const N: usize, G: KimchiCurve, OpeningProof: OpenProof<G>> {
    /// Polynomial commitments to the witness columns
    commitments: Witness<N, PolyComm<G>>,
    /// Evaluations of witness polynomials at current rows on random evaluation point `zeta`
    zeta_evaluations: Witness<N, G::ScalarField>,
    /// Evaluations of witness polynomials at next rows (where `* omega` comes from) on random evaluation point `zeta`
    zeta_omega_evaluations: Witness<N, G::ScalarField>,
    /// Proof of opening for the evaluations with respect to the polynomial commitments
    opening_proof: OpeningProof,
}

/// This function folds the witness of the current circuit with the accumulated Keccak instance
/// with a random combination using a scaling challenge
pub fn fold<
    const N: usize,
    G: KimchiCurve,
    OpeningProof: OpenProof<G>,
    EFqSponge: Clone + FqSponge<G::BaseField, G, G::ScalarField>,
    EFrSponge: FrSponge<G::ScalarField>,
>(
    domain: EvaluationDomains<G::ScalarField>,
    srs: &OpeningProof::SRS,
    accumulator: &mut ProofInputs<N, G>,
    inputs: &Witness<N, Vec<G::ScalarField>>,
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
            .collect::<Witness<N, _>>()
    };
    let mut fq_sponge = EFqSponge::new(G::other_curve_sponge_params());

    for column in commitments.into_iter() {
        absorb_commitment(&mut fq_sponge, &column);
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

/// This function provides a proof for a Keccak instance.
// TODO: this proof does not contain information about the constraints nor lookups yet
pub fn prove<
    const N: usize,
    G: KimchiCurve,
    OpeningProof: OpenProof<G>,
    EFqSponge: Clone + FqSponge<G::BaseField, G, G::ScalarField>,
    EFrSponge: FrSponge<G::ScalarField>,
>(
    domain: EvaluationDomains<G::ScalarField>,
    srs: &OpeningProof::SRS,
    inputs: ProofInputs<N, G>,
) -> Proof<N, G, OpeningProof>
where
    OpeningProof::SRS: Sync,
{
    let ProofInputs { evaluations } = inputs;
    let polys: Witness<N, _> = {
        let eval_col = |evals: Vec<G::ScalarField>| {
            Evaluations::<G::ScalarField, D<G::ScalarField>>::from_vec_and_domain(evals, domain.d1)
                .interpolate()
        };
        let eval_array_col = |evals: &[Vec<G::ScalarField>]| {
            evals
                .into_par_iter()
                .map(|e| eval_col(e.to_vec()))
                .collect::<Vec<_>>()
        };
        Witness {
            cols: eval_array_col(&evaluations.cols).try_into().unwrap(),
        }
    };
    let commitments = {
        let comm = |poly: &DensePolynomial<G::ScalarField>| srs.commit_non_hiding(poly, 1);
        let comm_array = |polys: &[DensePolynomial<G::ScalarField>]| {
            polys.into_par_iter().map(comm).collect::<Vec<_>>()
        };
        Witness {
            cols: comm_array(&polys.cols).try_into().unwrap(),
        }
    };

    let mut fq_sponge = EFqSponge::new(G::other_curve_sponge_params());

    for column in commitments.clone().into_iter() {
        absorb_commitment(&mut fq_sponge, &column);
    }
    let zeta_chal = ScalarChallenge(fq_sponge.challenge());
    let (_, endo_r) = G::endos();
    let zeta = zeta_chal.to_field(endo_r);
    let omega = domain.d1.group_gen;
    let zeta_omega = zeta * omega;

    let evals = |point| {
        let comm = |poly: &DensePolynomial<G::ScalarField>| poly.evaluate(point);
        let comm_array = |polys: &[DensePolynomial<G::ScalarField>]| {
            polys.par_iter().map(comm).collect::<Vec<_>>()
        };
        Witness {
            cols: comm_array(&polys.cols).try_into().unwrap(),
        }
    };
    let zeta_evaluations = evals(&zeta);
    let zeta_omega_evaluations = evals(&zeta_omega);
    let group_map = G::Map::setup();
    let polynomials = polys.into_iter().collect::<Vec<_>>();
    let polynomials: Vec<_> = polynomials
        .iter()
        .map(|poly| {
            (
                DensePolynomialOrEvaluations::DensePolynomial(poly),
                PolyComm {
                    elems: vec![G::ScalarField::zero()],
                },
            )
        })
        .collect();
    let fq_sponge_before_evaluations = fq_sponge.clone();
    let mut fr_sponge = EFrSponge::new(G::sponge_params());
    fr_sponge.absorb(&fq_sponge.digest());

    for (zeta_eval, zeta_omega_eval) in zeta_evaluations
        .clone()
        .into_iter()
        .zip(zeta_omega_evaluations.clone().into_iter())
    {
        fr_sponge.absorb(&zeta_eval);
        fr_sponge.absorb(&zeta_omega_eval);
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

/// This function verifies the proof of a Keccak instance.
// TODO: this still does not verify the constraints nor lookups
pub fn verify<
    const N: usize,
    G: KimchiCurve,
    OpeningProof: OpenProof<G>,
    EFqSponge: Clone + FqSponge<G::BaseField, G, G::ScalarField>,
    EFrSponge: FrSponge<G::ScalarField>,
>(
    domain: EvaluationDomains<G::ScalarField>,
    srs: &OpeningProof::SRS,
    proof: &Proof<N, G, OpeningProof>,
) -> bool {
    let Proof {
        commitments,
        zeta_evaluations,
        zeta_omega_evaluations,
        opening_proof,
    } = proof;

    let mut fq_sponge = EFqSponge::new(G::other_curve_sponge_params());
    for column in commitments.clone().into_iter() {
        absorb_commitment(&mut fq_sponge, &column);
    }
    let zeta_chal = ScalarChallenge(fq_sponge.challenge());
    let (_, endo_r) = G::endos();
    let zeta: G::ScalarField = zeta_chal.to_field(endo_r);
    let omega = domain.d1.group_gen;
    let zeta_omega = zeta * omega;

    let fq_sponge_before_evaluations = fq_sponge.clone();
    let mut fr_sponge = EFrSponge::new(G::sponge_params());
    fr_sponge.absorb(&fq_sponge.digest());

    let es: Vec<_> = {
        let mut evals = vec![];
        for (zeta, zeta_omega) in zeta_evaluations
            .clone()
            .into_iter()
            .zip(zeta_omega_evaluations.clone().into_iter())
        {
            evals.push(vec![vec![zeta], vec![zeta_omega]]);
        }
        evals
    };

    let evaluations: Vec<_> = {
        let mut evals = vec![];
        for (commitment, (zeta_eval, zeta_omega_eval)) in commitments.clone().into_iter().zip(
            zeta_evaluations
                .clone()
                .into_iter()
                .zip(zeta_omega_evaluations.clone().into_iter()),
        ) {
            evals.push(Evaluation {
                commitment: commitment.clone(),
                evaluations: vec![vec![zeta_eval], vec![zeta_omega_eval]],
            });
        }
        evals
    };

    for (zeta_eval, zeta_omega_eval) in zeta_evaluations
        .clone()
        .into_iter()
        .zip(zeta_omega_evaluations.clone().into_iter())
    {
        fr_sponge.absorb(&zeta_eval);
        fr_sponge.absorb(&zeta_omega_eval);
    }

    let v_chal = fr_sponge.challenge();
    let v = v_chal.to_field(endo_r);
    let u_chal = fr_sponge.challenge();
    let u = u_chal.to_field(endo_r);

    let combined_inner_product = combined_inner_product(&v, &u, es.as_slice());

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        keccak::column::{KeccakWitness, ZKVM_KECCAK_COLS},
        mips::column::{MIPSWitness, MIPS_COLUMNS},
    };

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

        let proof_inputs = {
            let cols = std::array::from_fn(|_| {
                (0..DOMAIN_SIZE).map(|_| Fp::rand(rng)).collect::<Vec<_>>()
            });
            ProofInputs {
                evaluations: MIPSWitness { cols },
            }
        };
        let domain = EvaluationDomains::<Fp>::create(DOMAIN_SIZE).unwrap();

        // Trusted setup toxic waste
        let x = Fp::rand(rng);

        let mut srs = PairingSRS::create(x, DOMAIN_SIZE);
        srs.full_srs.add_lagrange_basis(domain.d1);

        let proof = prove::<MIPS_COLUMNS, _, PairingProof<BN254Parameters>, BaseSponge, ScalarSponge>(
            domain,
            &srs,
            proof_inputs,
        );

        assert!(verify::<
            MIPS_COLUMNS,
            _,
            PairingProof<BN254Parameters>,
            BaseSponge,
            ScalarSponge,
        >(domain, &srs, &proof));
    }

    // Dummy test with random witness that verifies because the proof still does not include constraints nor lookups
    #[test]
    fn test_keccak_prover() {
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

        let proof_inputs = {
            ProofInputs {
                evaluations: KeccakWitness {
                    cols: std::array::from_fn(|_| {
                        (0..DOMAIN_SIZE).map(|_| Fp::rand(rng)).collect::<Vec<_>>()
                    }),
                },
            }
        };
        let domain = EvaluationDomains::<Fp>::create(DOMAIN_SIZE).unwrap();

        // Trusted setup toxic waste
        let x = Fp::rand(rng);

        let mut srs = PairingSRS::create(x, DOMAIN_SIZE);
        srs.full_srs.add_lagrange_basis(domain.d1);

        let proof: Proof<
            2074,
            ark_ec::short_weierstrass_jacobian::GroupAffine<ark_bn254::g1::Parameters>,
            PairingProof<ark_ec::bn::Bn<ark_bn254::Parameters>>,
        > = prove::<ZKVM_KECCAK_COLS, _, PairingProof<BN254Parameters>, BaseSponge, ScalarSponge>(
            domain,
            &srs,
            proof_inputs,
        );

        assert!(verify::<
            ZKVM_KECCAK_COLS,
            _,
            PairingProof<BN254Parameters>,
            BaseSponge,
            ScalarSponge,
        >(domain, &srs, &proof));
    }
}
