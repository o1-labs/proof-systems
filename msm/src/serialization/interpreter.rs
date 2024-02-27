pub trait InterpreterEnv {
    type Position;

    type Variable;

    /// Check that the value is in the range [0, 2^15-1]
    fn range_check15(&mut self, _value: &Self::Variable) {
        // TODO
    }

    /// Check that the value is in the range [0, 2^4-1]
    fn range_check4(&mut self, _value: &Self::Variable) {
        // TODO
    }

    /// Deserialize the next field element given as input
    fn deserialize_field_element(&mut self);
}
