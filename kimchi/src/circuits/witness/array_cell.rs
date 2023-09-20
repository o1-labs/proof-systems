use super::{variables::Variables, WitnessCell};
use ark_ff::Field;

/// Witness cell assigned from a variable
/// See [Variables] for more details
pub struct ArrayCell<'a> {
    name: &'a str,
    index: usize,
}

impl<'a> ArrayCell<'a> {
    /// Create witness cell assigned from a variable name
    pub fn create(name: &'a str, index: usize) -> Box<ArrayCell<'a>> {
        Box::new(ArrayCell { name, index })
    }
}

impl<'a, const N: usize, F: Field> WitnessCell<N, F, Vec<F>> for ArrayCell<'a> {
    fn value(&self, _witness: &mut [Vec<F>; N], variables: &Variables<Vec<F>>) -> F {
        variables[self.name][self.index]
    }
}
