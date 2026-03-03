//! A collection of utility functions and constants that can be reused from
//! multiple projects

// Enable unstable `is_multiple_of` on nightly for Wasm builds until nightly is updated
// See: https://github.com/o1-labs/mina-rust/issues/1997
#![cfg_attr(target_arch = "wasm32", feature(unsigned_is_multiple_of))]
#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]
#![deny(clippy::all)]
#![deny(clippy::pedantic)]
#![deny(clippy::nursery)]

extern crate alloc;

/// Returns a parallel iterator when the `parallel` feature is enabled,
/// otherwise returns a sequential iterator.
#[macro_export]
macro_rules! cfg_iter {
    ($e:expr) => {{
        #[cfg(feature = "parallel")]
        let result = $e.par_iter();
        #[cfg(not(feature = "parallel"))]
        let result = $e.iter();
        result
    }};
}

/// Returns a parallel mutable iterator when the `parallel` feature is enabled,
/// otherwise returns a sequential mutable iterator.
#[macro_export]
macro_rules! cfg_iter_mut {
    ($e:expr) => {{
        #[cfg(feature = "parallel")]
        let result = $e.par_iter_mut();
        #[cfg(not(feature = "parallel"))]
        let result = $e.iter_mut();
        result
    }};
}

/// Returns a parallel consuming iterator when the `parallel` feature is enabled,
/// otherwise returns a sequential consuming iterator.
#[macro_export]
macro_rules! cfg_into_iter {
    ($e:expr) => {{
        #[cfg(feature = "parallel")]
        let result = $e.into_par_iter();
        #[cfg(not(feature = "parallel"))]
        let result = $e.into_iter();
        result
    }};
}

pub mod adjacent_pairs;
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
#[cfg(feature = "std")]
pub use field_helpers::RandomField;
pub use field_helpers::{BigUintFieldHelpers, FieldHelpers, Two};
pub use foreign_field::ForeignElement;

/// Utils only for testing
#[cfg(feature = "std")]
pub mod tests {
    use rand::{rngs::StdRng, thread_rng, Rng, SeedableRng};

    /// Create a new test rng with a random seed
    #[must_use]
    pub fn make_test_rng(seed: Option<[u8; 32]>) -> StdRng {
        let seed = seed.unwrap_or_else(|| thread_rng().gen());
        eprintln!("Seed: {seed:?}");
        StdRng::from_seed(seed)
    }
}
