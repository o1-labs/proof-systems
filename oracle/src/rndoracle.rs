/*****************************************************************************************************************

This source file implements the random oracle argument API.

*****************************************************************************************************************/

pub use super::poseidon::{ArithmeticSponge, ArithmeticSpongeParams, Sponge};
use std::fmt;

// TODO(mimoo): move this out of oracle
#[derive(Debug, Clone, Copy)]
pub enum ProofError {
    NoRoomForZkInWitness,
    WitnessCsInconsistent,
    // TODO(mimoo): once this is moved, error can be propagated here
    WitnessGateError,
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
    ValueNotInTable,
    ProofInconsistentLookup,
}

// Implement `Display` for ProofError
impl fmt::Display for ProofError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "({:?})", self)
    }
}
