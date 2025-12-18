//! A collection of utility functions and constants that can be reused from
//! multiple projects

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

/// Creates an iterator that repeats an element `n` times.
/// This function is stable in Rust 1.82+ (lint exists since Rust 1.83+).
/// We keep a manual implementation for compatibility with older Rust versions.
/// TODO: Remove when updating to Rust 1.85+. See <https://github.com/o1-labs/mina-rust/issues/1951>
#[rustversion::attr(since(1.83), allow(clippy::manual_repeat_n))]
pub fn repeat_n<T: Clone>(element: T, count: usize) -> impl Iterator<Item = T> {
    core::iter::repeat(element).take(count)
}

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
