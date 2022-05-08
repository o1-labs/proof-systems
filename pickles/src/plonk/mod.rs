use ark_ec::AffineCurve;
use ark_ff::{FftField, PrimeField};

use oracle::sponge::ScalarChallenge;

/// Enforces gate constraints (rows checks)
mod gates;

/// Witness columns in Turbo-PlonK argument
const COLUMNS: usize = 15;

/// Number of columns in permutation argument
/// (remaining columns are gate-hints)
///
///
const PERMUTS: usize = 7;

pub struct Commits<A: AffineCurve> {
    /// Commitment to witness columns
    w: [A; COLUMNS],

    /// Commitment to permutation polynomial
    z: A,

    /// Commitment to quotient polynomial
    t: A,
}

/// We linearlize by:
///
/// 1. Opening the witness columns
/// 2. Evaluating the rows checks
/// 3. Convoluting with the selectors (part of the index)
pub struct Openings<F: FftField + PrimeField> {
    /// Opening of witness polynomial
    w: [F; COLUMNS],

    /// Opening of permutation polynomial
    z: F,

    /// Opening of permutation polynomials
    s: [F; PERMUTS - 1],

    /// Opening of generic selector
    generic_selector: F,

    /// Opening of Poseidon selector
    poseidon_selector: F,
}

/// Abstracted PlonK proof.
/// https://eprint.iacr.org/2019/953.pdf
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
///
/// Note: PlonK proofs are always recursively verified over A::BaseField,
/// defering the scalar field operations to the complement proof by committing to the field elements.
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
