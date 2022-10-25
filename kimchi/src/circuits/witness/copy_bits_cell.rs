use ark_ff::Field;
use o1_utils::FieldHelpers;

use super::{variables::Variables, WitnessCell};
use crate::circuits::polynomial::COLUMNS;

/// Witness cell copied from bits of another witness cell
pub struct CopyBitsCell {
    row: usize,
    col: usize,
    start: usize, // inclusive
    end: usize,   // exclusive
}

impl CopyBitsCell {
    /// Create witness cell copied from bits [start, end) of the witness cell at position (row, col)
    pub fn create(row: usize, col: usize, start: usize, end: usize) -> Box<CopyBitsCell> {
        Box::new(CopyBitsCell {
            row,
            col,
            start,
            end,
        })
    }
}

impl<F: Field> WitnessCell<F> for CopyBitsCell {
    fn value(&self, witness: &mut [Vec<F>; COLUMNS], _variables: &Variables<F>) -> F {
        F::from_bits(&witness[self.col][self.row].to_bits()[self.start..self.end])
            .expect("failed to deserialize field bits for copy bits cell")
    }
}
