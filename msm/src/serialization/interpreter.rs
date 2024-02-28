pub trait InterpreterEnv {
    type Position;

    type Variable: Clone
        + std::ops::Add<Self::Variable, Output = Self::Variable>
        + std::ops::Sub<Self::Variable, Output = Self::Variable>
        + std::ops::Mul<Self::Variable, Output = Self::Variable>
        + std::fmt::Debug;

    /// Check that the value is in the range [0, 2^15-1]
    fn range_check15(&mut self, _value: &Self::Variable) {
        // TODO
    }

    /// Check that the value is in the range [0, 2^4-1]
    fn range_check4(&mut self, _value: &Self::Variable) {
        // TODO
    }

    /// Extract the bits from the variable `x` between `highest_bit` and `lowest_bit`, and store
    /// the result in `position`.
    /// `lowest_bit` becomes the least-significant bit of the resulting value.
    fn bitmask(
        &mut self,
        x: &Self::Variable,
        highest_bit: u128,
        lowest_bit: u128,
        position: Self::Position,
    ) -> Self::Variable;

    /// Deserialize the next field element given as input
    fn deserialize_field_element(&mut self);

    /// Copy the value `value` in the column `position`
    fn copy(&mut self, _position: Self::Position, _value: Self::Variable) {
        // TODO
    }
}
