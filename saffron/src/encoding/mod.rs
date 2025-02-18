use std::time::Instant;

use ark_ec::AffineRepr;
use ark_ff::PrimeField;
use ark_poly::{Evaluations, Radix2EvaluationDomain};
use poly_commitment::{commitment::CommitmentCurve, ipa::SRS, PolyComm, SRS as _};

pub mod dense;
pub mod sparse;

/// A user is supposed to implement this trait for their state
/// The user has to choice to encode their state as they want.
/// The efficiency of the readand write operations will depend on the encoding.
pub trait AbstractState {
    /// Encode the state into field elements
    fn encode<F: PrimeField>(
        &self,
        domain: Radix2EvaluationDomain<F>,
    ) -> Evaluations<F, Radix2EvaluationDomain<F>>;

    /// The number of field elements that are required to encode the state
    fn encoded_length(&self) -> usize;
}

pub fn commit<State: AbstractState, E1: CommitmentCurve>(
    state: State,
    srs: SRS<E1>,
    domain: Radix2EvaluationDomain<<E1 as AffineRepr>::ScalarField>,
) -> PolyComm<E1> {
    // Encoding
    let start_time = Instant::now();
    let evaluations = state.encode::<<E1 as AffineRepr>::ScalarField>(domain);
    let elapsed = start_time.elapsed();
    println!(
        "Encoding time: {:?}. {} bytes encoded in {} field elements",
        elapsed,
        state.encoded_length(),
        evaluations.evals.len()
    );

    // Committing
    let start_time = Instant::now();
    let commitments = srs.commit_evaluations_non_hiding(domain, &evaluations);
    let elapsed = start_time.elapsed();
    println!("Commit time: {:?}", elapsed);
    commitments
}
