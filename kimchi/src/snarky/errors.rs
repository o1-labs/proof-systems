use thiserror::Error;

/// A result type for Snarky errors.
pub type SnarkyResult<T> = std::result::Result<T, SnarkyError>;

/// A result type for Snarky runtime errors.
pub type SnarkyRuntimeResult<T> = std::result::Result<T, SnarkyRuntimeError>;

/// A result type for Snarky compilation errors.
pub type SnarkyCompileResult<T> = std::result::Result<T, SnarkyCompilationError>;

/// Snarky errors can come from either a compilation or runtime error.
#[derive(Debug, Clone, Error)]
pub enum SnarkyError {
    #[error("a compilation error occurred")]
    CompilationError(SnarkyCompilationError),

    #[error("a runtime error occurred")]
    RuntimeError(SnarkyRuntimeError),
}

/// Errors that can occur during compilation of a circuit.
#[derive(Debug, Clone, Error)]
pub enum SnarkyCompilationError {
    #[error("the two values were not equal: {0} != {1}")]
    ConstantAssertEquals(String, String),
}

/// Errors that can occur during runtime (proving).
#[derive(Debug, Clone, Error)]
pub enum SnarkyRuntimeError {
    #[error(
        "unsatisfied constraint: `{0} * {1} + {2} * {3} + {4} * {5} + {6} * {1} * {3} + {7} != 0`"
    )]
    UnsatisfiedGenericConstraint(
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        String,
    ),

    #[error("unsatisfied constraint: {0} is not a boolean (0 or 1)")]
    UnsatisfiedBooleanConstraint(String),

    #[error("unsatisfied constraint: {0} is not equal to {1}")]
    UnsatisfiedEqualConstraint(String, String),

    #[error("unsatisfied constraint: {0}^2 is not equal to {1}")]
    UnsatisfiedSquareConstraint(String, String),

    #[error("unsatisfied constraint: {0} * {1} is not equal to {2}")]
    UnsatisfiedR1CSConstraint(String, String, String),

    #[error("the number of public inputs passed ({0}) does not match the number of public inputs expected ({1})")]
    PubInputMismatch(usize, usize),

    #[error("the value returned by the circuit has an incorrect number of field variables. It hardcoded {1} field variables, but returned {0}")]
    CircuitReturnVar(usize, usize),
}
