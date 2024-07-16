/// The maximum degree of the polynomial that can be represented by the
/// polynomial-time function the library supports.
pub const MAX_DEGREE: u64 = 2;

pub mod column_env;
pub mod columns;
pub mod constraints;
pub mod interpreter;
pub mod proof;
pub mod prover;
pub mod verifier;
pub mod witness;
