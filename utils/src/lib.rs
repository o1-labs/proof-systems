//! A collection of utility functions and constants that can be reused from
//! multiple projects

// Enable unstable `is_multiple_of` on nightly for Wasm builds until nightly is updated
// See: https://github.com/o1-labs/mina-rust/issues/1997
#![cfg_attr(target_arch = "wasm32", feature(unsigned_is_multiple_of))]

pub mod adjacent_pairs;
pub mod array;
pub mod biguint_helpers;
pub mod bitwise_operations;
pub mod chunked_evaluations;
pub mod chunked_polynomial;
pub mod dense_polynomial;
pub mod evaluations;
pub mod field_helpers;
pub mod foreign_field;
pub mod hasher;
pub mod lazy_cache;
pub mod math;
pub mod serialization;

pub use biguint_helpers::BigUintHelpers;
pub use bitwise_operations::BitwiseOps;
pub use chunked_evaluations::ChunkedEvaluations;
pub use dense_polynomial::ExtendedDensePolynomial;
pub use evaluations::ExtendedEvaluations;
pub use field_helpers::{BigUintFieldHelpers, FieldHelpers, RandomField, Two};
pub use foreign_field::ForeignElement;

/// Utils only for testing
pub mod tests {
    use rand::{rngs::StdRng, thread_rng, Rng, SeedableRng};

    /// Create a new test rng with a random seed
    pub fn make_test_rng(seed: Option<[u8; 32]>) -> StdRng {
        let seed = seed.unwrap_or(thread_rng().gen());
        eprintln!("Seed: {:?}", seed);
        StdRng::from_seed(seed)
    }
}
