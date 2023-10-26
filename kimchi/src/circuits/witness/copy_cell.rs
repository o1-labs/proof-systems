use ark_ff::Field;

use super::{variables::Variables, WitnessCell};

/// Witness cell copied from another witness cell
pub struct CopyCell {
    row: usize,
    col: usize,
}

impl CopyCell {
    /// Create a witness cell copied from the witness cell at position (row, col)
    pub fn create(row: usize, col: usize) -> Box<CopyCell> {
        Box::new(CopyCell { row, col })
    }
}

impl<F: Field, const W: usize> WitnessCell<F, F, W> for CopyCell {
    fn value(&self, witness: &mut [Vec<F>; W], _variables: &Variables<F>, _index: usize) -> F {
        witness[self.col][self.row]
    }
}
