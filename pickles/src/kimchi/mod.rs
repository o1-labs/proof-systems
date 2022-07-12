use ark_ec::AffineCurve;
use ark_ff::{FftField, PrimeField};

use oracle::sponge::ScalarChallenge;

mod alphas;

/// Code to handle generic gates:
/// Generic gates do not use the expression framework :(
mod constraints;

pub mod index;

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
