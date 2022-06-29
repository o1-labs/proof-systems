use ark_ec::AffineCurve;
use ark_ff::{FftField, PrimeField};

use oracle::sponge::ScalarChallenge;

mod alphas;

mod misc;

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
