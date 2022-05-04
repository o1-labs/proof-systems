use ark_ff::{FftField, PrimeField};
use oracle::sponge::ScalarChallenge;

/// Abstracted PlonK proof.
/// https://eprint.iacr.org/2019/953.pdf
/// 
/// A PlonK proof over a general field, 
/// agnostic to the underlaying polynomial commitment scheme.
/// 
/// The relation verified by the PlonK proofs in Pickles are:
/// 
/// 1. Application logic: if in "step".
/// 2. Accumulation verifier: of the complement proof.
/// 3. PlonK verifier: of the complement proof.
/// 
/// TODO: some of these should be Endoscalar challenges 
/// to verify the PlonK proof more efficiently
pub struct Plonk<F: PrimeField + FftField> {
    // round 2: permutation challenges
    gamma: ScalarChallenge<F>,
    beta: ScalarChallenge<F>, 

    // round 3: quotient challenge
    alpha: F,

    // round 4: evaluation challenge
    // the verifier checks the relations between the provided
    // polynomials by requresting the opening at a random point and checking over the field;
    // soundness by Swartz-Zippel.
    zetta: F,

    // round 5: opening challenge
    v: F,
    u: F,
}