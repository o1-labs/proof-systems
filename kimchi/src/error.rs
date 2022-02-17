//! This module implements the [ProofError] type.

use thiserror::Error;

/// The result of a proof creation or verification.
pub type Result<T> = std::result::Result<T, ProofError>;

// TODO(mimoo): move this out of oracle
#[derive(Error, Debug, Clone, Copy)]
pub enum ProofError {
    #[error("the circuit is too large")]
    NoRoomForZkInWitness,
    #[error("the witness columns are not all the same size")]
    WitnessCsInconsistent,
    #[error("the polynomial `{0}` could not be divided by the vanishing polynomial")]
    PolyDivision(&'static str),
    #[error("the polynomial `{0}` divided by the vanishing polynomial does not have rest zero")]
    PolyDivisionRest(&'static str),
    #[error("the permutation was not constructed correctly: {0}")]
    Permutation(&'static str),
    #[error("the opening proof failed to verify")]
    OpenProof,
    #[error("the lookup failed to find a match in the table")]
    ValueNotInTable,
}
