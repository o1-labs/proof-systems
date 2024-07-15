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

/// Run an iteration of the IVC scheme.
/// It consists of the following steps:
/// 1. Compute the hash of the public input.
/// 2. Compute the elliptic curve addition.
/// 3. Run the polynomial-time function.
/// 4. Compute the hash of the output.
/// The environment is updated over time.
/// When the environment is the one described in the [Witness
/// environment](crate::witness::Env), the structure will be updated
/// with the new accumulator, the new public input, etc. The public output will
/// be in the structure also. The user can simply rerun the function for the
/// next iteration.
pub fn run<E: InterpreterEnv>(_env: &mut E) {}
