use super::{variables::Variables, WitnessCell};
use crate::circuits::polynomial::COLUMNS;
use ark_ff::Field;

/// A chunk of witness cells assigned from a variable that is an array
/// See [Variables] for more details
pub struct ArrayCell<'a> {
    name: &'a str,
    length: usize,
}

impl<'a> ArrayCell<'a> {
    /// Create witness cell assigned from a variable name
    pub fn create(name: &'a str, length: usize) -> Box<ArrayCell<'a>> {
        Box::new(ArrayCell { name, length })
    }
}

impl<'a, F: Field> WitnessCell<F> for ArrayCell<'a> {
    fn value(&self, _witness: &mut [Vec<F>; COLUMNS], variables: &Variables<F>) -> F {
        variables[self.name]
    }
}
