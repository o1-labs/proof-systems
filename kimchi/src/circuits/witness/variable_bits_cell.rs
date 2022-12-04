use super::{variables::Variables, WitnessCell};
use crate::circuits::polynomial::COLUMNS;
use ark_ff::Field;
use o1_utils::FieldHelpers;

/// Witness cell assigned from bits of a variable
/// See [Variables] for more details
pub struct VariableBitsCell<'a> {
    name: &'a str,
    start: usize, // inclusive
    end: usize,   // exclusive
}

impl<'a> VariableBitsCell<'a> {
    /// Create witness cell assigned from the bits [start, end) of named variable
    pub fn create(name: &'a str, start: usize, end: usize) -> Box<VariableBitsCell<'a>> {
        Box::new(VariableBitsCell { name, start, end })
    }
}

impl<'a, F: Field> WitnessCell<F> for VariableBitsCell<'a> {
    fn value(&self, _witness: &mut [Vec<F>; COLUMNS], variables: &Variables<F>) -> F {
        F::from_bits(&variables[self.name].to_bits()[self.start..self.end])
            .expect("failed to deserialize field bits for variable bits cell")
    }
}
