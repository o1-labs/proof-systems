/*****************************************************************************************************************

This source file implements the random oracle argument API.

*****************************************************************************************************************/

use std::fmt;
pub use super::poseidon::{ArithmeticSpongeParams, ArithmeticSponge, Sponge};

#[derive(Debug, Clone, Copy)]
pub enum ProofError
{
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
    RuntimeEnv
}

// Implement `Display` for ProofError
impl fmt::Display for ProofError
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result
    {
        write!(f, "({})", self)
    }
}
