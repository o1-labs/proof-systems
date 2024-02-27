use crate::{
    commitment::{
        combined_inner_product, BatchEvaluationProof, BlindedCommitment, CommitmentCurve,
        Evaluation, PolyComm,
    },
    evaluation_proof::{DensePolynomialOrEvaluations, OpeningProof},
    srs::SRS,
    SRS as _,
};
use ark_ff::{UniformRand, Zero};
use ark_poly::{univariate::DensePolynomial, Radix2EvaluationDomain, UVPolynomial};
use colored::Colorize;
use groupmap::GroupMap;
use mina_curves::pasta::{Fp, Vesta, VestaParameters};
use mina_poseidon::constants::PlonkSpongeConstantsKimchi as SC;
use mina_poseidon::sponge::DefaultFqSponge;
use mina_poseidon::FqSponge as _;
use o1_utils::ExtendedDensePolynomial as _;
use rand::{CryptoRng, Rng, SeedableRng};
use std::time::{Duration, Instant};

// Note: Because the current API uses large tuples of types, I re-create types
// in this test to facilitate aggregated proofs and batch verification of proofs.
// TODO: improve the polynomial commitment API

/// A commitment
pub struct Commitment {
    /// the commitment itself, potentially in chunks
    chunked_commitment: PolyComm<Vesta>,
}

/// An evaluated commitment (given a number of evaluation points)
pub struct EvaluatedCommitment {
    /// the commitment
    commit: Commitment,
    /// the chunked evaluations given in the same order as the evaluation points
    chunked_evals: Vec<ChunkedCommitmentEvaluation>,
}

/// A polynomial commitment evaluated at a point. Since a commitment can be chunked, the evaluations can also be chunked.
pub type ChunkedCommitmentEvaluation = Vec<Fp>;

mod prover {
    use super::*;

    /// This struct represents a commitment with associated secret information
    pub struct CommitmentAndSecrets {
        /// the commitment evaluated at some points
        pub eval_commit: EvaluatedCommitment,
        /// the polynomial
        pub poly: DensePolynomial<Fp>,
        /// the blinding part
        pub chunked_blinding: PolyComm<Fp>,
    }
}

/// This struct represents an aggregated evaluation proof for a number of polynomial commitments, as well as a number of evaluation points.
pub struct AggregatedEvaluationProof {
    /// a number of evaluation points
    eval_points: Vec<Fp>,
    /// a number of commitments evaluated at these evaluation points
    eval_commitments: Vec<EvaluatedCommitment>,
    /// the random value used to separate polynomials
    polymask: Fp,
    /// the random value used to separate evaluations
    evalmask: Fp,
    /// an Fq-sponge
    fq_sponge: DefaultFqSponge<VestaParameters, SC>,
    /// the actual evaluation proof
    proof: OpeningProof<Vesta>,
}

impl AggregatedEvaluationProof {
    /// This function converts an aggregated evaluation proof into something the verify API understands
    pub fn verify_type(
        &self,
    ) -> BatchEvaluationProof<Vesta, DefaultFqSponge<VestaParameters, SC>, OpeningProof<Vesta>>
    {
        let mut coms = vec![];
        for eval_com in &self.eval_commitments {
            assert_eq!(self.eval_points.len(), eval_com.chunked_evals.len());
            coms.push(Evaluation {
                commitment: eval_com.commit.chunked_commitment.clone(),
                evaluations: eval_com.chunked_evals.clone(),
            });
        }

        let combined_inner_product = {
            let es: Vec<_> = coms
                .iter()
                .map(|Evaluation { evaluations, .. }| evaluations.clone())
                .collect();
            combined_inner_product(&self.polymask, &self.evalmask, &es)
        };

        BatchEvaluationProof {
            sponge: self.fq_sponge.clone(),
            evaluation_points: self.eval_points.clone(),
            polyscale: self.polymask,
            evalscale: self.evalmask,
            evaluations: coms,
            opening: &self.proof,
            combined_inner_product,
        }
    }
}

fn test_randomised<RNG: Rng + CryptoRng>(mut rng: &mut RNG) {
    let group_map = <Vesta as CommitmentCurve>::Map::setup();
    let fq_sponge = DefaultFqSponge::<VestaParameters, SC>::new(
        mina_poseidon::pasta::fq_kimchi::static_params(),
    );

    // create an SRS optimized for polynomials of degree 2^7 - 1
    let srs = SRS::<Vesta>::create(1 << 7);

    let num_chunks = 1;

    // TODO: move to bench
    let mut time_commit = Duration::new(0, 0);
    let mut time_open = Duration::new(0, 0);

    // create 7 distinct "aggregated evaluation proofs"
    let mut proofs = vec![];
    for _ in 0..7 {
        // generate 7 random evaluation points
        let eval_points: Vec<Fp> = (0..7).map(|_| Fp::rand(&mut rng)).collect();

        // create 11 polynomials of random degree (of at most 500)
        // and commit to them
        let mut commitments = vec![];
        for _ in 0..11 {
            let len: usize = rng.gen();
            let len = len % 500;
            // TODO @volhovm maybe remove the second case.
            // every other polynomial is upperbounded
            let poly = if len == 0 {
                DensePolynomial::<Fp>::zero()
            } else {
                DensePolynomial::<Fp>::rand(len, &mut rng)
            };

            // create commitments for each polynomial, and evaluate each polynomial at the 7 random points
            let timer = Instant::now();
            let BlindedCommitment {
                commitment: chunked_commitment,
                blinders: chunked_blinding,
            } = srs.commit(&poly, num_chunks, &mut rng);
            time_commit += timer.elapsed();

            let mut chunked_evals = vec![];
            for point in eval_points.clone() {
                chunked_evals.push(
                    poly.to_chunked_polynomial(1, srs.g.len())
                        .evaluate_chunks(point),
                );
            }

            let commit = Commitment { chunked_commitment };

            let eval_commit = EvaluatedCommitment {
                commit,
                chunked_evals,
            };

            commitments.push(prover::CommitmentAndSecrets {
                eval_commit,
                poly,
                chunked_blinding,
            });
        }

        // create aggregated evaluation proof
        #[allow(clippy::type_complexity)]
        let mut polynomials: Vec<(
            DensePolynomialOrEvaluations<Fp, Radix2EvaluationDomain<Fp>>,
            PolyComm<_>,
        )> = vec![];
        for c in &commitments {
            polynomials.push((
                DensePolynomialOrEvaluations::DensePolynomial(&c.poly),
                c.chunked_blinding.clone(),
            ));
        }

        let polymask = Fp::rand(&mut rng);
        let evalmask = Fp::rand(&mut rng);

        let timer = Instant::now();
        let proof = srs.open::<DefaultFqSponge<VestaParameters, SC>, _, _>(
            &group_map,
            &polynomials,
            &eval_points.clone(),
            polymask,
            evalmask,
            fq_sponge.clone(),
            &mut rng,
        );
        time_open += timer.elapsed();

        // prepare for batch verification
        let eval_commitments = commitments.into_iter().map(|c| c.eval_commit).collect();
        proofs.push(AggregatedEvaluationProof {
            eval_points,
            eval_commitments,
            polymask,
            evalmask,
            fq_sponge: fq_sponge.clone(),
            proof,
        });
    }

    println!("{} {:?}", "total commitment time:".yellow(), time_commit);
    println!(
        "{} {:?}",
        "total evaluation proof creation time:".magenta(),
        time_open
    );

    let timer = Instant::now();

    // batch verify all the proofs
    let mut batch: Vec<_> = proofs.iter().map(|p| p.verify_type()).collect();
    assert!(srs.verify::<DefaultFqSponge<VestaParameters, SC>, _>(&group_map, &mut batch, &mut rng));

    // TODO: move to bench
    println!(
        "{} {:?}",
        "batch verification time:".green(),
        timer.elapsed()
    );
}

#[test]
/// Tests polynomial commitments, batched openings and
/// verification of a batch of batched opening proofs of polynomial commitments
fn test_commit()
where
    <Fp as std::str::FromStr>::Err: std::fmt::Debug,
{
    // setup
    let mut rng = rand::thread_rng();
    test_randomised(&mut rng)
}

#[test]
/// Deterministic tests of polynomial commitments, batched openings and
/// verification of a batch of batched opening proofs of polynomial commitments
fn test_commit_deterministic()
where
    <Fp as std::str::FromStr>::Err: std::fmt::Debug,
{
    // Seed deliberately chosen to exercise zero commitments
    let seed = [
        17, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ];

    let mut rng = <rand_chacha::ChaCha20Rng as SeedableRng>::from_seed(seed);
    test_randomised(&mut rng)
}
