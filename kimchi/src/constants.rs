/// Number of constraints produced by the permutation argument.
pub const PERM_CONSTRAINTS: u32 = 3;
/// The number of points that are evaluated in the protocol (zeta and zeta * omega).
pub const EVALS: u64 = 2;
/// The permutation constraint should not apply on the final row  
/// (not including [ZK_ROWS] otherwise it will wrap around.  
/// We only need to check the final value of the permutation accumulator  
/// on the final row.  
/// Ref: https://o1-labs.github.io/proof-systems/plonk/zkpm.html
pub const PERM_FINAL_ACC: u64 = 1;
/// The number of rows that are added to a witness/circuit in order to provide zero-knowledge.
pub const ZK_ROWS: u64 = EVALS + PERM_FINAL_ACC;
