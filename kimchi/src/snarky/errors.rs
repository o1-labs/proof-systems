use thiserror::Error;

#[derive(Debug, Clone)]
pub enum SnarkyError<F> {
    /// A compilation error occurred.
    CompilationError(SnarkyCompilationError<F>),

    /// A runtime error occurred.
    RuntimeError(SnarkyRuntimeError<F>),
}

#[derive(Debug, Clone, Error)]
pub enum SnarkyCompilationError<F> {
    ToDelete(F),
}

#[derive(Debug, Clone, Error)]
pub enum SnarkyRuntimeError<F> {
    /// unsatisfied constraint:
    /// `{0} * {1} + {2} * {3} + {4} * {5} + {6} * {7} + {8} != 0`
    UnsatisfiedGenericConstraint(F, F, F, F, F, F, F, F),

    /// unsatisfied constraint: {0} is not a boolean (0 or 1)
    UnsatisfiedBooleanConstraint(F),

    /// unsatisfied constraint: {0} is not equal to {1}
    UnsatisfiedEqualConstraint(F, F),

    /// unsatisfied constraint: {0}^2 is not equal to {1}
    UnsatisfiedSquareConstraint(F, F),

    /// unsatisfied constraint: {0} * {1} is not equal to {2}
    UnsatisfiedR1CSConstraint(F, F, F),
}
