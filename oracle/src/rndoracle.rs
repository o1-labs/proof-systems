/*****************************************************************************************************************

This source file implements the random oracle argument API.

*****************************************************************************************************************/

pub use super::poseidon::{ArithmeticSponge, ArithmeticSpongeParams, Sponge};
use std::fmt;

#[derive(Debug, Clone, Copy)]
pub enum ProofError {
    WitnessCsInconsistent,
    DomainCreation,
    PolyDivision,
    PolyCommit,
    PolyCommitWithBound,
    PolyExponentiate,
    ProofCreation,
    ProofVerification,
    OpenProof,
    SumCheck,
    ConstraintInconsist,
    EvaluationGroup,
    OracleCommit,
    RuntimeEnv,
}

// Implement `Display` for ProofError
impl fmt::Display for ProofError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "({:?})", self)
    }
}
