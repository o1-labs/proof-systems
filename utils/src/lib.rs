#![warn(missing_docs)]
#![doc = include_str!("../README.md")]

pub mod dense_polynomial;
pub mod evaluations;
pub mod serialization;

pub use dense_polynomial::ExtendedDensePolynomial;
pub use evaluations::ExtendedEvaluations;
