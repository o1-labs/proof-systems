use ark_ff::{One, Zero};
use num_bigint::BigInt;

pub trait InterpreterEnv {
    type Position: Clone + Copy;

    type Variable: Clone
        + core::ops::Add<Self::Variable, Output = Self::Variable>
        + core::ops::Sub<Self::Variable, Output = Self::Variable>
        + core::ops::Mul<Self::Variable, Output = Self::Variable>
        + core::fmt::Debug
        + Zero
        + One;

    fn allocate(&mut self) -> Self::Position;

    fn allocate_next_row(&mut self) -> Self::Position;

    fn read_position(&self, pos: Self::Position) -> Self::Variable;

    fn write_column(&mut self, col: Self::Position, v: Self::Variable) -> Self::Variable;

    fn zero(&self) -> Self::Variable;

    fn one(&self) -> Self::Variable;

    fn constant(&self, v: BigInt) -> Self::Variable;

    fn assert_zero(&mut self, x: Self::Variable);

    fn assert_equal(&mut self, x: Self::Variable, y: Self::Variable);

    fn add_constraint(&mut self, x: Self::Variable);

    fn constrain_boolean(&mut self, x: Self::Variable);

    fn square(&mut self, res: Self::Position, x: Self::Variable) -> Self::Variable;

    fn bitmask_be(
        &mut self,
        x: &Self::Variable,
        highest_bit: u32,
        lowest_bit: u32,
        position: Self::Position,
    ) -> Self::Variable;

    fn reset(&mut self);

    fn inverse(&mut self, pos: Self::Position, x: Self::Variable) -> Self::Variable;
}
