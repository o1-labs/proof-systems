use super::{variables::Variables, WitnessCell};
use ark_ff::Field;

/// Witness cell assigned from an indexable variable
/// See [Variables] for more details
pub struct IndexCell<'a> {
    name: &'a str,
    index: usize,
}

impl<'a> IndexCell<'a> {
    /// Create witness cell assigned from a variable name
    pub fn create(name: &'a str, index: usize) -> Box<IndexCell<'a>> {
        Box::new(IndexCell { name, index })
    }
}

impl<'a, const N: usize, F: Field> WitnessCell<N, F, Vec<F>> for IndexCell<'a> {
    fn value(&self, _witness: &mut [Vec<F>; N], variables: &Variables<Vec<F>>) -> F {
        variables[self.name][self.index]
    }
}
