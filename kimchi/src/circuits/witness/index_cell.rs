use super::{variables::Variables, WitnessCell};
use ark_ff::Field;

/// Witness cell assigned from an indexable variable
/// See [Variables] for more details
pub struct IndexCell<'a> {
    name: &'a str,
    length: usize,
}

impl<'a> IndexCell<'a> {
    /// Create witness cell assigned from a variable name a length
    pub fn create(name: &'a str, from: usize, to: usize) -> Box<IndexCell<'a>> {
        Box::new(IndexCell {
            name,
            length: to - from,
        })
    }
}

impl<F: Field, const W: usize> WitnessCell<F, Vec<F>, W> for IndexCell<'_> {
    fn value(&self, _witness: &mut [Vec<F>; W], variables: &Variables<Vec<F>>, index: usize) -> F {
        assert!(index < self.length, "index out of bounds of `IndexCell`");
        variables[self.name][index]
    }
    fn length(&self) -> usize {
        self.length
    }
}
