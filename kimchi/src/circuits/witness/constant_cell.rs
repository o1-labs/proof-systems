use super::{variables::Variables, WitnessCell};
use ark_ff::Field;

/// Witness cell with constant value
pub struct ConstantCell<F: Field> {
    value: F,
}

impl<F: Field> ConstantCell<F> {
    /// Create witness cell with constant value
    pub fn create(value: F) -> Box<ConstantCell<F>> {
        Box::new(ConstantCell { value })
    }
}

impl<F: Field, const W: usize> WitnessCell<F, F, W> for ConstantCell<F> {
    fn value(&self, _witness: &mut [Vec<F>; W], _variables: &Variables<F>, _index: usize) -> F {
        self.value
    }
}
