use std::{backtrace::Backtrace, borrow::Cow};

use thiserror::Error;

/// A result type for Snarky errors.
pub type SnarkyResult<T> = core::result::Result<T, Box<RealSnarkyError>>;

/// A result type for Snarky runtime errors.
pub type SnarkyRuntimeResult<T> = core::result::Result<T, Box<SnarkyRuntimeError>>;

/// A result type for Snarky compilation errors.
pub type SnarkyCompileResult<T> = core::result::Result<T, SnarkyCompilationError>;

#[derive(Debug, Error)]
#[error("an error occurred in snarky")]
pub struct RealSnarkyError {
    /// The actual error.
    pub source: SnarkyError,

    /// A location string, usually a file name and line number.
    /// Location information is usually useful for:
    ///
    /// - assert that failed (so we need to keep track of the location that created each gates)
    pub loc: Option<String>,

    /// A stack of labels,
    /// where each label represents an important function call.
    pub label_stack: Option<Vec<Cow<'static, str>>>,

    /// A Rust backtrace of where the error came from.
    /// This can be especially useful for debugging snarky when wrapped by a different language implementation.
    backtrace: Option<Backtrace>,
}

impl RealSnarkyError {
    /// Creates a new [RealSnarkyError].
    pub fn new(source: SnarkyError) -> Self {
        let backtrace = std::env::var("SNARKY_BACKTRACE")
            .ok()
            .map(|_| Backtrace::capture());
        Self {
            source,
            loc: None,
            label_stack: None,
            backtrace,
        }
    }

    /// Creates a new [RealSnarkyError].
    pub fn new_with_ctx(
        source: SnarkyError,
        loc: Cow<'static, str>,
        label_stack: Vec<Cow<'static, str>>,
    ) -> Self {
        let backtrace = std::env::var("SNARKY_BACKTRACE")
            .ok()
            .map(|_| Backtrace::capture());

        Self {
            source,
            loc: Some(loc.to_string()),
            label_stack: Some(label_stack),
            backtrace,
        }
    }
}

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
        "unsatisfied constraint #{8}: `{0} * {1} + {2} * {3} + {4} * {5} + {6} * {1} * {3} + {7} != 0`"
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
        usize,
    ),

    #[error("unsatisfied constraint #{0}: {1} is not a boolean (0 or 1)")]
    UnsatisfiedBooleanConstraint(usize, String),

    #[error("unsatisfied constraint #{0}: {1} is not equal to {2}")]
    UnsatisfiedEqualConstraint(usize, String, String),

    #[error("unsatisfied constraint #{0}: {1}^2 is not equal to {2}")]
    UnsatisfiedSquareConstraint(usize, String, String),

    #[error("unsatisfied constraint #{0}: {1} * {2} is not equal to {3}")]
    UnsatisfiedR1CSConstraint(usize, String, String, String),

    #[error("the number of public inputs passed ({0}) does not match the number of public inputs expected ({1})")]
    PubInputMismatch(usize, usize),

    #[error("the value returned by the circuit has an incorrect number of field variables. It hardcoded {1} field variables, but returned {0}")]
    CircuitReturnVar(usize, usize),
}
