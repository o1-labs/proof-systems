/// The maximum degree of the polynomial that can be represented by the
/// polynomial-time function the library supports.
pub const MAX_DEGREE: u64 = 2;

/// The minimum SRS size required to use Nova, in base 2.
// FIXME: that might change.
pub const MIN_SRS_LOG2_SIZE: usize = 15;

/// The number of rows the IVC circuit requires.
// FIXME: that might change. We use a vertical layout for now.
pub const IVC_CIRCUIT_SIZE: usize = 1 << 13;

/// The maximum number of columns that can be used in the circuit.
pub const NUMBER_OF_COLUMNS: usize = 50;

pub mod column_env;
pub mod columns;
pub mod constraints;
pub mod interpreter;
pub mod logup;
pub mod proof;
pub mod prover;
pub mod verifier;
pub mod witness;
