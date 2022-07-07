//! Foreign field multiplication witness computation

use ark_ff::PrimeField;
use array_init::array_init;
use num_bigint::BigUint;
use o1_utils::foreign_field::field_element_to_native_limbs;

use crate::circuits::{
    polynomial::COLUMNS,
    polynomials::range_check::{
        self, handle_standard_witness_cell, value_to_limb, CopyWitnessCell, ZeroWitnessCell,
    },
};

// Extend standard WitnessCell to support foreign field multiplication
// specific cell types
//
//     * Shift     := value is copied from another cell and right shifted (little-endian)
//     * ValueLimb := contiguous range of bits extracted a value
//
// TODO: Currently located in range check, but could be moved
//       elsewhere so other gates could reuse
pub enum WitnessCell {
    Standard(range_check::WitnessCell),
    Shift(ShiftWitnessCell),
    ValueLimb(ValueLimbWitnessCell),
}

// Witness cell copied and shifted from another
pub struct ShiftWitnessCell {
    row: usize,
    col: usize,
    shift: usize,
}

impl ShiftWitnessCell {
    pub const fn create(row: usize, col: usize, shift: usize) -> WitnessCell {
        WitnessCell::Shift(ShiftWitnessCell { row, col, shift })
    }
}

// Witness cell containing a limb of a value
pub struct ValueLimbWitnessCell {
    start: usize,
    end: usize,
}

impl ValueLimbWitnessCell {
    pub const fn create(start: usize, end: usize) -> WitnessCell {
        WitnessCell::ValueLimb(ValueLimbWitnessCell { start, end })
    }
}

// Witness layout
//   * The values and cell contents are in little-endian order, which
//     is important for compatibility with other gates.
//   * The witness sections for the multi range check gates should be set up
//     so that the last range checked value is the MS limb of the respective
//     foreign field element.  For example, given foreign field element q
//     such that
//
//         q = q0 + 2^88 * q1 + 2^176 * q2
//
//     and multi-range-check gate witness W, where W[r][c] accesses row r
//     and column c, we should map q to W like this
//
//         W[0][0] = q0
//         W[1][0] = q1
//         W[2][0] = q2
//
//     so that most significant limb, q2, is in W[2][0].
//
const WITNESS_SHAPE: [[WitnessCell; COLUMNS]; 2] = [
    // ForeignFieldMul row
    [
        WitnessCell::Standard(CopyWitnessCell::create(0, 0)), // left_input_lo
        WitnessCell::Standard(CopyWitnessCell::create(1, 0)), // left_input_mid
        WitnessCell::Standard(CopyWitnessCell::create(2, 0)), // left_input_hi
        ShiftWitnessCell::create(10, 0, 9),                   // carry_shift
        ShiftWitnessCell::create(10, 0, 8),                   // quotient_shift
        // TODO: Anais
        WitnessCell::Standard(ZeroWitnessCell::create()),
        WitnessCell::Standard(ZeroWitnessCell::create()),
        ValueLimbWitnessCell::create(0, 88), // product_mid_bottom
        WitnessCell::Standard(ZeroWitnessCell::create()),
        WitnessCell::Standard(ZeroWitnessCell::create()),
        WitnessCell::Standard(ZeroWitnessCell::create()),
        WitnessCell::Standard(ZeroWitnessCell::create()),
        WitnessCell::Standard(ZeroWitnessCell::create()),
        WitnessCell::Standard(ZeroWitnessCell::create()),
        WitnessCell::Standard(ZeroWitnessCell::create()),
    ],
    // Zero row
    [
        // TODO: Joseph
        WitnessCell::Standard(ZeroWitnessCell::create()),
        WitnessCell::Standard(ZeroWitnessCell::create()),
        WitnessCell::Standard(ZeroWitnessCell::create()),
        WitnessCell::Standard(ZeroWitnessCell::create()),
        WitnessCell::Standard(ZeroWitnessCell::create()),
        WitnessCell::Standard(ZeroWitnessCell::create()),
        WitnessCell::Standard(ZeroWitnessCell::create()),
        WitnessCell::Standard(ZeroWitnessCell::create()),
        WitnessCell::Standard(ZeroWitnessCell::create()),
        WitnessCell::Standard(ZeroWitnessCell::create()),
        WitnessCell::Standard(ZeroWitnessCell::create()),
        WitnessCell::Standard(ZeroWitnessCell::create()),
        WitnessCell::Standard(ZeroWitnessCell::create()),
        WitnessCell::Standard(ZeroWitnessCell::create()),
        WitnessCell::Standard(ZeroWitnessCell::create()),
    ],
];

fn init_foreign_filed_multiplication_row<F: PrimeField>(
    witness: &mut [Vec<F>; COLUMNS],
    row: usize,
    value: F,
) {
    for col in 0..COLUMNS {
        match &WITNESS_SHAPE[row][col] {
            WitnessCell::Standard(standard_cell) => {
                handle_standard_witness_cell(witness, standard_cell, row, col, value)
            }
            WitnessCell::Shift(shift_cell) => {
                todo!()
                // TODO: Joseph
            }
            WitnessCell::ValueLimb(value_limb_cell) => {
                witness[col][row] = value_to_limb(
                    value,                 // value
                    value_limb_cell.start, // starting bit
                    value_limb_cell.end,   // ending bit (exclusive)
                );
            }
        }
    }
}

/// Create a foreign field multiplication witness
/// Input: multiplicands left_input and right_input
pub fn create_witness<F: PrimeField>(
    left_input: BigUint,
    right_input: BigUint,
) -> [Vec<F>; COLUMNS] {
    let mut witness: [Vec<F>; COLUMNS] = array_init(|_| vec![F::zero(); 2]);

    // Create multi-range-check witness for left_input and right_input
    range_check::extend_witness(&mut witness, left_input);
    range_check::extend_witness(&mut witness, right_input);

    // TODO: Compute quotient and remainder

    // Create foreign field multiplication rows witness

    witness
}
