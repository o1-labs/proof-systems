pub trait InterpreterEnv {
    type Position;

    type Variable;

    fn range_check64(&mut self, _value: &Self::Variable) {
        // TODO
    }

    fn deserialize_field_element(&mut self);
}
