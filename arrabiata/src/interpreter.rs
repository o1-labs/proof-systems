use ark_ff::{One, Zero};

/// For the IVC circuit, we need different gadgets in addition to run the
/// polynomial-time function:
/// - Hash: we need compute the hash of the public input, which is the output of
/// the previous instance.
/// - Elliptic curve addition: we need to compute the elliptic curve operation.
pub trait InterpreterEnv {
    type Position;

    type Variable: Clone
        + std::ops::Add<Self::Variable, Output = Self::Variable>
        + std::ops::Sub<Self::Variable, Output = Self::Variable>
        + std::ops::Mul<Self::Variable, Output = Self::Variable>
        + std::fmt::Debug
        + Zero
        + One;

    fn variable(&self, position: Self::Position) -> Self::Variable;

    fn add_constraint(&mut self, constraint: Self::Variable);
}
