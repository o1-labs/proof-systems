use ark_ff::{FftField, PrimeField};
use ark_ec::AffineCurve;

use oracle::sponge::ScalarChallenge;

/// Enforces gate constraints (rows checks)
mod gates;

/// Witness columns in Turbo-PlonK argument
const COLUMNS: usize = 15;

/// Number of columns in permutation argument
/// (remaining columns are gate-hints)
/// 
/// 
const PERMUTS_MINUS_1: usize = 6;

pub struct Commits<A: AffineCurve> {
    witness: [A; COLUMNS],
    s: [A; PERMUTS_MINUS_1],
    z: A,
}

/// We linearlize by:
/// 
/// 1. Opening the witness columns
/// 2. Evaluating the rows checks
/// 3. Convoluting with the selectors (part of the index)
pub struct Openings<F: FftField + PrimeField> {
    witness: [F; COLUMNS],
}

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
/// 
/// QUESTION: what is the "Poseidon selector"?
pub struct Plonk<A: AffineCurve> {
    comm: Commits<A>,
    open: Openings<A::ScalarField>,

    // round 2: permutation challenges
    gamma: ScalarChallenge<A::ScalarField>,
    beta: ScalarChallenge<A::ScalarField>,

    // round 3: quotient challenge
    alpha: A::ScalarField,

    // round 4: evaluation challenge
    // the verifier checks the relations between the provided
    // polynomials by requresting the opening at a random point and checking over the field;
    // soundness by Swartz-Zippel.
    zetta: A::ScalarField,

    // round 5: opening challenge
    v: A::ScalarField,
    u: A::ScalarField,
}
