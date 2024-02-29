pub trait InterpreterEnv {
    type Position;

    type Variable: Clone
        + std::ops::Add<Self::Variable, Output = Self::Variable>
        + std::ops::Sub<Self::Variable, Output = Self::Variable>
        + std::ops::Mul<Self::Variable, Output = Self::Variable>
        + std::fmt::Debug;

    fn copy(&mut self, x: &Self::Variable, position: Self::Position) -> Self::Variable;

    fn get_column_for_kimchi_limb(j: usize) -> Self::Position;

    fn get_column_for_intermediate_limb(j: usize) -> Self::Position;

    fn get_column_for_msm_limb(j: usize) -> Self::Position;

    /// Check that the value is in the range [0, 2^15-1]
    fn range_check15(&mut self, _value: &Self::Variable) {
        // TODO
    }

    /// Check that the value is in the range [0, 2^4-1]
    fn range_check4(&mut self, _value: &Self::Variable) {
        // TODO
    }

    fn constant(value: u128) -> Self::Variable;

    /// Extract the bits from the variable `x` between `highest_bit` and `lowest_bit`, and store
    /// the result in `position`.
    /// `lowest_bit` becomes the least-significant bit of the resulting value.
    /// The value `x` is expected to be encoded in big-endian
    fn bitmask_be(
        &mut self,
        x: &Self::Variable,
        highest_bit: u32,
        lowest_bit: u32,
        position: Self::Position,
    ) -> Self::Variable;
}
