use super::{variables::Variables, WitnessCell};
use crate::circuits::polynomial::COLUMNS;
use ark_ff::Field;
use o1_utils::FieldHelpers;

/// Witness cell assigned from a variable and a nybble (4bit) index
/// See [Variables] for more details
pub struct NybbleCell<'a> {
    name: &'a str,
    nybble: usize,
}

impl<'a> NybbleCell<'a> {
    /// Create witness cell assigned from a variable name and a nybble index.
    /// The value of the witness will be the variable from bit 4*nybble until the end.
    pub fn create(name: &'a str, nybble: usize) -> Box<NybbleCell<'a>> {
        Box::new(NybbleCell { name, nybble })
    }
}

impl<'a, F: Field> WitnessCell<F> for NybbleCell<'a> {
    fn value(&self, _witness: &mut [Vec<F>; COLUMNS], variables: &Variables<F>) -> F {
        F::from_bits(&variables[self.name].to_bits()[16 * self.nybble..])
            .expect("failed to deserialize field bits for nybble cell")
    }
}
