use super::{variables::Variables, WitnessCell};
use ark_ff::Field;
use o1_utils::FieldHelpers;

/// Witness cell assigned from bits of a variable
/// See [Variables] for more details
pub struct VariableBitsCell<'a> {
    name: &'a str,
    start: usize,       // inclusive
    end: Option<usize>, // exclusive
}

impl<'a> VariableBitsCell<'a> {
    /// Create witness cell assigned from the bits [start, end) of named variable.
    /// If end is None, then the final bit corresponds to the position of the highest bit of the variable.
    pub fn create(name: &'a str, start: usize, end: Option<usize>) -> Box<VariableBitsCell<'a>> {
        Box::new(VariableBitsCell { name, start, end })
    }
}

impl<F: Field, const W: usize> WitnessCell<F, F, W> for VariableBitsCell<'_> {
    fn value(&self, _witness: &mut [Vec<F>; W], variables: &Variables<F>, _index: usize) -> F {
        let bits = if let Some(end) = self.end {
            F::from_bits(&variables[self.name].to_bits()[self.start..end])
        } else {
            F::from_bits(&variables[self.name].to_bits()[self.start..])
        };
        bits.expect("failed to deserialize field bits for variable bits cell")
    }
}
