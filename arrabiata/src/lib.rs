/// The maximum degree of the polynomial that can be represented by the
/// polynomial-time function the library supports.
pub const MAX_DEGREE: u64 = 5;

/// The minimum SRS size required to use Nova, in base 2.
/// Requiring at least 2^16 to perform 16bits range checks.
pub const MIN_SRS_LOG2_SIZE: usize = 16;

/// The number of rows the IVC circuit requires.
// FIXME: that might change. We use a vertical layout for now.
pub const IVC_CIRCUIT_SIZE: usize = 1 << 13;

/// The maximum number of columns that can be used in the circuit.
pub const NUMBER_OF_COLUMNS: usize = 17;

/// The maximum number of public inputs the circuit can use per row
// FIXME: that might change
pub const NUMBER_OF_PUBLIC_INPUTS: usize = 3;

pub mod column_env;
pub mod columns;
pub mod constraints;
pub mod interpreter;
pub mod logup;
pub mod proof;
pub mod prover;
pub mod verifier;
pub mod witness;
