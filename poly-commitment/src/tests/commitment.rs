use crate::{
    commitment::{BatchEvaluationProof, BlindedCommitment, CommitmentCurve, Evaluation, PolyComm},
    evaluation_proof::OpeningProof,
    srs::SRS,
};
use ark_ff::{UniformRand, Zero};
use ark_poly::{univariate::DensePolynomial, UVPolynomial};
use colored::Colorize;
use groupmap::GroupMap;
use mina_curves::pasta::{
    vesta::{Affine, VestaParameters},
    Fp,
};
use o1_utils::ExtendedDensePolynomial as _;
use oracle::constants::PlonkSpongeConstantsKimchi as SC;
use oracle::sponge::DefaultFqSponge;
use oracle::FqSponge as _;
use rand::Rng;
use std::time::{Duration, Instant};

// Note: Because the current API uses large tuples of types, I re-create types
// in this test to facilitate aggregated proofs and batch verification of proofs.
// TODO: improve the polynomial commitment API

/// A commitment
pub struct Commitment {
    /// the commitment itself, potentially in chunks
    chunked_commitment: PolyComm<Affine>,
    /// an optional degree bound
    bound: Option<usize>,
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
pub struct AggregatedEvaluationProof<'a> {
    /// a number of evaluation points
    eval_points: Vec<Fp>,
    /// a number of commitments evaluated at these evaluation points
    eval_commitments: Vec<EvaluatedCommitment>,
    /// the random value used to separate polynomials
    polymask: Fp,
    /// the random value used to separate evaluations
    evalmask: Fp,
    /// an Fq-sponge
    fq_sponge: DefaultFqSponge<'a, VestaParameters, SC>,
    /// the actual evaluation proof
    proof: OpeningProof<Affine>,
}

impl<'a> AggregatedEvaluationProof<'a> {
    /// This function converts an aggregated evaluation proof into something the verify API understands
    pub fn verify_type(
        &self,
    ) -> BatchEvaluationProof<Affine, DefaultFqSponge<VestaParameters, SC>> {
        let mut coms = vec![];
        for eval_com in &self.eval_commitments {
            assert_eq!(self.eval_points.len(), eval_com.chunked_evals.len());
            coms.push(Evaluation {
                commitment: eval_com.commit.chunked_commitment.clone(),
                evaluations: eval_com.chunked_evals.clone(),
                degree_bound: eval_com.commit.bound,
            });
        }

        BatchEvaluationProof {
            sponge: self.fq_sponge.clone(),
            evaluation_points: self.eval_points.clone(),
            xi: self.polymask,
            r: self.evalmask,
            evaluations: coms,
            opening: &self.proof,
        }
    }
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
    let group_map = <Affine as CommitmentCurve>::Map::setup();
    let fq_sponge = DefaultFqSponge::<VestaParameters, SC>::new(oracle::pasta::fq_kimchi_params());

    // create an SRS optimized for polynomials of degree 2^7 - 1
    let srs = SRS::<Affine>::create(1 << 7);

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
        for i in 0..11 {
            let len: usize = rng.gen();
            let len = len % 500;
            let poly = if len == 0 {
                DensePolynomial::<Fp>::zero()
            } else {
                DensePolynomial::<Fp>::rand(len, &mut rng)
            };

            // every other polynomial is upperbounded
            let bound = if i % 2 == 0 {
                Some(poly.coeffs.len())
            } else {
                None
            };

            // create commitments for each polynomial, and evaluate each polynomial at the 7 random points
            let timer = Instant::now();
            let BlindedCommitment {
                commitment: chunked_commitment,
                blinders: chunked_blinding,
            } = srs.commit(&poly, bound, &mut rng);
            time_commit += timer.elapsed();

            let mut chunked_evals = vec![];
            for point in eval_points.clone() {
                chunked_evals.push(
                    poly.to_chunked_polynomial(srs.g.len())
                        .evaluate_chunks(point),
                );
            }

            let commit = Commitment {
                chunked_commitment,
                bound,
            };

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
        let mut polynomials = vec![];
        for c in &commitments {
            polynomials.push((
                &c.poly,
                c.eval_commit.commit.bound,
                c.chunked_blinding.clone(),
            ));
        }

        let polymask = Fp::rand(&mut rng);
        let evalmask = Fp::rand(&mut rng);

        let timer = Instant::now();
        let proof = srs.open::<DefaultFqSponge<VestaParameters, SC>, _>(
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
