//! This is the pickles flavor of the o1vm.
//! The goal of this flavor is to run a version of the o1vm with selectors for
//! each instruction using the Pasta curves and the IPA PCS.
//!
//! A proof is generated for each set of N continuous instructions, where N is
//! the size of the supported SRS. The proofs will then be aggregated using
//! a modified version of pickles.
//!
//! You can run this flavor by using:
//!
//! ```bash
//! O1VM_FLAVOR=pickles bash run-code.sh
//! ```

pub mod column_env;
pub mod lookup_columns;
pub mod lookup_env;
pub mod lookup_prover;
pub mod proof;
pub mod prover;
pub mod verifier;

/// Degree of the quotient polynomial. We do evaluate all polynomials on d8
/// (because of the value of [MAXIMUM_DEGREE_CONSTRAINTS]), and therefore, we do
/// have a degree 7 for the quotient polynomial.
/// Used to keep track of the number of chunks we do have when we commit to the
/// quotient polynomial.
pub const DEGREE_QUOTIENT_POLYNOMIAL: u64 = 7;

/// Total number of constraints for all instructions, including the constraints
/// added for the selectors.
pub const TOTAL_NUMBER_OF_CONSTRAINTS: usize = 466;

#[cfg(test)]
mod tests;
