use super::{variables::Variables, WitnessCell};
use crate::circuits::polynomial::COLUMNS;
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

impl<F: Field> WitnessCell<F> for ConstantCell<F> {
    fn value(&self, _witness: &mut [Vec<F>; COLUMNS], _variables: &Variables<F>) -> F {
        self.value
    }
}
