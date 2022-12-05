use ark_ff::Field;
use o1_utils::FieldHelpers;

use super::{variables::Variables, WitnessCell};
use crate::circuits::polynomial::COLUMNS;

/// Witness cell that copies bits from another cell and adds a constant to it
pub struct SumCopyBitsCell<F: Field> {
    row: usize,
    col: usize,
    start: usize, // inclusive
    end: usize,   // exclusive
    sum: F,       // value added to the (row,col) cell
}

impl<F: Field> SumCopyBitsCell<F> {
    /// Create witness cell copied from bits [start, end) of the witness cell at position (row, col) with a constant to be summed
    pub fn create(
        row: usize,
        col: usize,
        start: usize,
        end: usize,
        sum: F,
    ) -> Box<SumCopyBitsCell<F>> {
        Box::new(SumCopyBitsCell::<F> {
            row,
            col,
            start,
            end,
            sum,
        })
    }
}

impl<F: Field> WitnessCell<F> for SumCopyBitsCell<F> {
    fn value(&self, witness: &mut [Vec<F>; COLUMNS], _variables: &Variables<F>) -> F {
        F::from_bits(&(witness[self.col][self.row] + self.sum).to_bits()[self.start..self.end])
            .expect("failed to deserialize field bits for copy bits cell")
    }
}
