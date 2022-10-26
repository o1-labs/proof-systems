use super::{variables::Variables, WitnessCell};
use crate::circuits::polynomial::COLUMNS;
use ark_ff::Field;
use o1_utils::FieldHelpers;

/// Witness cell assigned from a variable and a crumb index
/// See [Variables] for more details
pub struct CrumbCell<'a> {
    name: &'a str,
    crumb: usize,
}

impl<'a> CrumbCell<'a> {
    /// Create witness cell assigned from a variable name and a crumb index.
    /// The value of the witness will be the variable from bit 4*crumb until the end.
    pub fn create(name: &'a str, crumb: usize) -> Box<CrumbCell<'a>> {
        Box::new(CrumbCell { name, crumb })
    }
}

impl<'a, F: Field> WitnessCell<F> for CrumbCell<'a> {
    fn value(&self, _witness: &mut [Vec<F>; COLUMNS], variables: &Variables<F>) -> F {
        F::from_bits(&variables[self.name].to_bits()[16 * self.crumb..])
            .expect("failed to deserialize field bits for crumb cell")
    }
}
