//! This module implements the [ProverError] type.

use thiserror::Error;

/// Errors that can arise when creating a proof
// TODO(mimoo): move this out of oracle
#[derive(Error, Debug, Clone, Copy)]
pub enum ProverError {
    #[error("the circuit is too large")]
    NoRoomForZkInWitness,

    #[error("the witness columns are not all the same size")]
    WitnessCsInconsistent,

    #[error("the proof could not be constructed: {0}")]
    Prover(&'static str),

    #[error("the permutation was not constructed correctly: {0}")]
    Permutation(&'static str),

    #[error("the lookup failed to find a match in the table")]
    ValueNotInTable,

    #[error("kimchi does not support SRS of size smaller than the domain")]
    SRSTooSmall,
}

/// Errors that can arise when verifying a proof
#[derive(Error, Debug, Clone, Copy)]
pub enum VerifyError {
    #[error("the commitment to {0} is of an unexpected size")]
    IncorrectCommitmentLength(&'static str),

    #[error("the opening proof failed to verify")]
    OpenProof,

    #[error("lookup used in circuit, but proof is missing lookup commitments")]
    LookupCommitmentMissing,

    #[error("lookup used in circuit, but proof is missing lookup evaluations")]
    LookupEvalsMissing,

    #[error("lookup used in circuit, but proof has inconsistent number of lookup evaluations and commitments")]
    ProofInconsistentLookup,

    #[error("kimchi does not support batching verification of proofs of different SRS")]
    DifferentSRS,

    #[error("kimchi does not support SRS of size smaller than the domain")]
    SRSTooSmall,
}

/// Errors that can arise when preparing the setup
#[derive(Error, Debug, Clone)]
pub enum SetupError {
    #[error("the domain could not be constructed: {0}")]
    ConstraintSystem(String),

    #[error("the domain could not be constructed: {0}")]
    DomainCreation(&'static str),
}
