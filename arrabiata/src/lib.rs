/// The maximum degree of the polynomial that can be represented by the
/// polynomial-time function the library supports.
pub const MAX_DEGREE: u64 = 2;

/// The minimum SRS size required to use Nova, in base 2.
// FIXME: that might change.
pub const MIN_SRS_LOG2_SIZE: usize = 15;

pub mod column_env;
pub mod columns;
pub mod constraints;
pub mod interpreter;
pub mod proof;
pub mod prover;
pub mod verifier;
pub mod witness;
