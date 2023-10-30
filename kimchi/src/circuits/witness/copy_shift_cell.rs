use super::{variables::Variables, WitnessCell};
use ark_ff::Field;

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

impl<F: Field, const W: usize> WitnessCell<F, F, W> for CopyShiftCell {
    fn value(&self, witness: &mut [Vec<F>; W], _variables: &Variables<F>, _index: usize) -> F {
        F::from(2u32).pow([self.shift]) * witness[self.col][self.row]
    }
}
