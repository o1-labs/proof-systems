use super::{variables::Variables, WitnessCell};
use crate::circuits::polynomial::COLUMNS;
use ark_ff::Field;
use o1_utils::Two;

/// Witness cell copied from another cell and shifted
pub struct CopyShiftCell {
    row: usize,
    col: usize,
    shift: u64,
}

impl CopyShiftCell {
    /// Create witness cell copied from the witness cell at position (row, col) and then scaled by 2^shift
    pub fn create(row: usize, col: usize, shift: u64) -> Box<CopyShiftCell> {
        Box::new(CopyShiftCell { row, col, shift })
    }
}

impl<F: Field> WitnessCell<F> for CopyShiftCell {
    fn value(&self, witness: &mut [Vec<F>; COLUMNS], _variables: &Variables<F>) -> F {
        F::two_pow(self.shift) * witness[self.col][self.row]
    }
}
