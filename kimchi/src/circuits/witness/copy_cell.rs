use ark_ff::Field;

use super::{variables::Variables, WitnessCell};
use crate::circuits::polynomial::COLUMNS;

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

impl<F: Field> WitnessCell<F> for CopyCell {
    fn value(&self, witness: &mut [Vec<F>; COLUMNS], _variables: &Variables<F>) -> F {
        witness[self.col][self.row]
    }
}
