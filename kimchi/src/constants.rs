//! Kimchi proving system constants
//!

/// The number of points that are evaluated in the protocol (zeta and zeta * omega).
pub const EVALS: u64 = 2;

/// The number of rows that are added to a witness/circuit in order to provide zero-knowledge.
/// This number is eqaul to [EVALS] since you need to add as many random rows as there are evaluations in the protocol, to add zero-knowledgeness.
pub const ZK_ROWS: u64 = EVALS;

/// The number of rows that are added to check that the permutation accumulator is 0 or 1.
/// The permutation constraint should not apply on the final row  
/// (not including [ZK_ROWS] otherwise it will wrap around.  
/// We only need to check the final value of the permutation accumulator  
/// on the final row.  
/// Ref: https://o1-labs.github.io/proof-systems/plonk/zkpm.html
pub const PERMUTATION_ACC: u64 = 1;

/// The number of rows that are used for zero-knowledgeness in Kimchi protocol.
/// We use [PERMUTATION_ACC] row as additional zk row since no witness can be used on that row.
pub const WITNESS_ZK_ROWS: u64 = ZK_ROWS + PERMUTATION_ACC;
