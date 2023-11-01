use super::{variables::Variables, WitnessCell};
use ark_ff::Field;

/// Witness cell assigned from a variable
/// See [Variables] for more details
pub struct VariableCell<'a> {
    name: &'a str,
}

impl<'a> VariableCell<'a> {
    /// Create witness cell assigned from a variable name
    pub fn create(name: &'a str) -> Box<VariableCell<'a>> {
        Box::new(VariableCell { name })
    }
}

impl<'a, F: Field, const COLUMNS: usize> WitnessCell<F, F, COLUMNS> for VariableCell<'a> {
    fn value(
        &self,
        _witness: &mut [Vec<F>; COLUMNS],
        variables: &Variables<F>,
        _index: usize,
    ) -> F {
        variables[self.name]
    }
}
