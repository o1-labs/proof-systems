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
pub trait AbstractState<F: PrimeField> {
    /// Encode the state into field elements
    fn encode(
        &self,
        domain: Radix2EvaluationDomain<F>,
    ) -> Vec<Evaluations<F, Radix2EvaluationDomain<F>>>;

    /// The number of field elements that are required to encode the state
    fn encoded_length(&self) -> usize;

    fn sub(
        self,
        other: Self,
        domain: Radix2EvaluationDomain<F>,
    ) -> Vec<Evaluations<F, Radix2EvaluationDomain<F>>>;
}

pub fn commit<E1: CommitmentCurve, State: AbstractState<<E1 as AffineRepr>::ScalarField>>(
    state: State,
    srs: SRS<E1>,
    domain: Radix2EvaluationDomain<<E1 as AffineRepr>::ScalarField>,
) -> Vec<PolyComm<E1>> {
    // Encoding
    let start_time = Instant::now();
    let evaluations: Vec<
        Evaluations<
            <E1 as AffineRepr>::ScalarField,
            Radix2EvaluationDomain<<E1 as AffineRepr>::ScalarField>,
        >,
    > = state.encode(domain);
    let elapsed = start_time.elapsed();
    println!(
        "Encoding time: {:?}. {} bytes encoded in {} field elements",
        elapsed,
        state.encoded_length(),
        evaluations.len() * domain.size as usize
    );

    // Committing
    let start_time = Instant::now();
    let commitments = evaluations
        .iter()
        .map(|eval| srs.commit_evaluations_non_hiding(domain, eval))
        .collect();
    let elapsed = start_time.elapsed();
    println!("Commit time: {:?}", elapsed);
    commitments
}

pub fn compute_diff<E1: CommitmentCurve, State: AbstractState<<E1 as AffineRepr>::ScalarField>>(
    state_before: State,
    state_after: State,
    domain: Radix2EvaluationDomain<<E1 as AffineRepr>::ScalarField>,
) -> Vec<PolyComm<E1>> {
    let _diff = state_before.sub(state_after, domain);
    // FIXME: commit when non zero
    // The commitments to the diffs are way smaller if we have a sparse state
    // for bytes. We can also avoid using the encoding into montgomery form and
    // speed up the commitments as we we will only have to commit to values [0,
    // 255] * G_i, and the diff will still be between [0, 255] * G_i.
    // (if we have to commit to (x - y)) and x > y, x - y will be in [0, 255],
    // and committing is fast. If y > x, we can commit to (y - x) and negate the
    // commitment. Pretty fast.
    vec![]
}
