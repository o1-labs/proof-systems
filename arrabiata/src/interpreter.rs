//! This module contains the implementation of the IVC scheme in addition to
//! running an arbitrary function that can use up to [crate::NUMBER_OF_COLUMNS]
//! columns.

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

    /// Allocate a new variable in the circuit
    fn allocate(&mut self) -> Self::Position;

    /// Build a variable from the given position
    fn variable(&self, position: Self::Position) -> Self::Variable;

    /// Assert that the variable is zero
    fn assert_zero(&mut self, x: Self::Variable);

    /// Assert that the two variables are equal
    fn assert_equal(&mut self, x: Self::Variable, y: Self::Variable);

    fn add_constraint(&mut self, x: Self::Variable);

    /// Compute the square a field element
    fn square(&mut self, res: Self::Position, x: Self::Variable) -> Self::Variable;

    /// Fetch an input of the application
    // Witness-only
    fn fetch_input(&mut self, res: Self::Position) -> Self::Variable;

    /// Reset the environment to build the next row
    fn reset(&mut self);

    /// Reset the environment to build the next iteration
    fn reset_for_next_iteration(&mut self);
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
/// A row must be created to generate a challenge to combine the constraints
/// later. The challenge will be also accumulated over time.
pub fn run_app<E: InterpreterEnv>(env: &mut E) {
    let x1 = {
        let pos = env.allocate();
        env.fetch_input(pos)
    };
    let _x1_square = {
        let res = env.allocate();
        env.square(res, x1.clone())
    };
    env.reset();
}
