use ark_ff::{One, Zero};

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
