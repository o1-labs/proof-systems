use ark_ec::AffineCurve;
use ark_ff::{FftField, PrimeField};

use oracle::sponge::ScalarChallenge;

mod index;

// General "Var" types
// (e.g. an evaluation of a polynomial as a variable)
mod types;

/// Proof types
pub mod proof;

/// Verifier logic
mod verifier;

/// Witness columns
const COLUMNS: usize = 15;

/// Size of challenges in bits
const CHALLENGE_LEN: usize = 128;

///
const SELECTORS: usize = 15;

/// Number of columns in permutation argument
/// (remaining columns are gate-hints for non-deterministic computation)
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
pub struct Proof<A: AffineCurve> {
    comm: Commits<A>,

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

    // commitment to quotient polynomial $t$
    t_comm: A,

    // round 5: opening challenge
    v: A::ScalarField,
    u: A::ScalarField,
}
