//! This module implements the [`ProverError`] type.

use crate::circuits::lookup::index::LookupError; // not sure about hierarchy
use o1_utils::lazy_cache::{LazyCacheError, LazyCacheErrorOr};
use poly_commitment::error::CommitmentError;
use thiserror::Error;

/// Errors that can arise when creating a proof
// TODO(mimoo): move this out of oracle
#[derive(Error, Debug, Clone)]
pub enum ProverError {
    #[error("the circuit is too large")]
    NoRoomForZkInWitness,

    #[error(
        "there are not enough random rows to achieve zero-knowledge (expected: {0}, got: {1})"
    )]
    NotZeroKnowledge(usize, usize),

    #[error("the witness columns are not all the same size")]
    WitnessCsInconsistent,

    #[error("the proof could not be constructed: {0}")]
    Prover(&'static str),

    #[error("the permutation was not constructed correctly: {0}")]
    Permutation(&'static str),

    #[error("the lookup failed to find a match in the table: row={0}")]
    ValueNotInTable(usize),

    #[error("the runtime tables provided did not match the index's configuration")]
    RuntimeTablesInconsistent,

    #[error("wrong number of custom blinders given: {0}")]
    WrongBlinders(CommitmentError),

    #[error("relation polynomials failed to initialize in lazy mode: {0}")]
    LazySetup(SetupError),
}

/// Errors that can arise when verifying a proof
#[derive(Error, Debug, Clone, Copy)]
pub enum VerifyError {
    #[error("the commitment to {0} is of an unexpected size (expected {1}, got {2})")]
    IncorrectCommitmentLength(&'static str, usize, usize),

    #[error("the public input is of an unexpected size (expected {0})")]
    IncorrectPubicInputLength(usize),

    #[error("the previous challenges have an unexpected length (expected {0}, got {1})")]
    IncorrectPrevChallengesLength(usize, usize),

    #[error(
        "proof malformed: an evaluation for {2} was of the incorrect size (expected {0}, got {1})"
    )]
    IncorrectEvaluationsLength(usize, usize, &'static str),

    #[error("the opening proof failed to verify")]
    OpenProof,

    #[error("lookup used in circuit, but proof is missing lookup commitments")]
    LookupCommitmentMissing,

    #[error("lookup used in circuit, but proof is missing lookup evaluations")]
    LookupEvalsMissing,

    #[error("lookup used in circuit, but proof has inconsistent number of lookup evaluations and commitments")]
    ProofInconsistentLookup,

    #[error("cannot batch proofs using different SRSes")]
    DifferentSRS,

    #[error("SRS size is smaller than the domain size required by the circuit")]
    SRSTooSmall,

    #[error("runtime tables are used, but missing from the proof")]
    IncorrectRuntimeProof,

    #[error("the evaluation for {0:?} is missing")]
    MissingEvaluation(crate::circuits::berkeley_columns::Column),

    #[error("the evaluation for PublicInput is missing")]
    MissingPublicInputEvaluation,

    #[error("the commitment for {0:?} is missing")]
    MissingCommitment(crate::circuits::berkeley_columns::Column),
}

/// Errors that can arise when preparing the setup
#[derive(Error, Debug, Clone)]
pub enum DomainCreationError {
    #[error("could not compute the size of domain for {0}")]
    DomainSizeFailed(usize),

    #[error("construction of domain {0} for size {1} failed")]
    DomainConstructionFailed(String, usize),
}

/// Errors that can arise when preparing the setup
#[derive(Error, Debug, Clone)]
pub enum SetupError {
    #[error("the domain could not be constructed: {0}")]
    ConstraintSystem(String),

    #[error("the domain could not be constructed: {0}")]
    DomainCreation(DomainCreationError),

    #[error("the lookup constraint system cannot not be constructed: {0}")]
    LookupCreation(LookupError),

    #[error("lazy evaluation failed")]
    LazyEvaluation(LazyCacheError),
}

/// Errors that can arise when creating a verifier index
#[derive(Error, Debug, Clone)]
pub enum VerifierIndexError {
    #[error("srs has already been set")]
    SRSHasBeenSet,
}

// Handling of lookup errors happening inside creation of LookupConstraintSystem
impl From<LazyCacheErrorOr<LookupError>> for SetupError {
    fn from(e: LazyCacheErrorOr<LookupError>) -> Self {
        match e {
            LazyCacheErrorOr::Inner(inner) => SetupError::LookupCreation(inner.clone()),
            LazyCacheErrorOr::Outer(err) => SetupError::LazyEvaluation(err),
        }
    }
}

impl From<LazyCacheErrorOr<LookupError>> for ProverError {
    fn from(e: LazyCacheErrorOr<LookupError>) -> Self {
        ProverError::LazySetup(SetupError::from(e))
    }
}
