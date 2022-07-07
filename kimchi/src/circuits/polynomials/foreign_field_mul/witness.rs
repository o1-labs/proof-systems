//! Foreign field multiplication witness computation

use crate::circuits::{
    polynomial::COLUMNS,
    polynomials::range_check::{
        self, handle_standard_witness_cell, value_to_limb, CopyWitnessCell, ZeroWitnessCell,
    },
};
use ark_ff::PrimeField;
use array_init::array_init;
use num_bigint::BigUint;
use o1_utils::foreign_field::LIMB_BITS;

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
pub enum ValueType {
    ProductMid,
    Carry,
}
pub struct ValueLimbWitnessCell {
    kind: ValueType,
    start: usize,
    end: usize,
}

impl ValueLimbWitnessCell {
    pub const fn create(kind: ValueType, start: usize, end: usize) -> WitnessCell {
        WitnessCell::ValueLimb(ValueLimbWitnessCell { kind, start, end })
    }
}

// Witness layout
//   * The values and cell contents are in little-endian order, which
//     is important for compatibility with other gates.
//   * The witness sections for the multi range check gates should be set up
//     so that the last range checked value is the MS limb of the respective
//     foreign field element. For example, given foreign field element q
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
        ShiftWitnessCell::create(20, 0, 9),                   // carry_shift
        ShiftWitnessCell::create(10, 0, 8),                   // quotient_shift
        WitnessCell::Standard(CopyWitnessCell::create(8, 0)), // quotient_lo
        WitnessCell::Standard(CopyWitnessCell::create(9, 0)), // quotient_mid
        WitnessCell::Standard(CopyWitnessCell::create(10, 0)), // quotient_hi
        ValueLimbWitnessCell::create(ValueType::ProductMid, 0, LIMB_BITS), // product_mid_bottom
        ValueLimbWitnessCell::create(ValueType::ProductMid, LIMB_BITS, 2 * LIMB_BITS), // product_mid_top_limb
        ValueLimbWitnessCell::create(ValueType::ProductMid, 2 * LIMB_BITS, 2 * LIMB_BITS + 2), // product_mid_top_extra
        WitnessCell::Standard(range_check::ValueWitnessCell::create()), // carry_bottom
        ValueLimbWitnessCell::create(ValueType::Carry, 0, LIMB_BITS),   // carry_top_limb
        ValueLimbWitnessCell::create(ValueType::Carry, LIMB_BITS, LIMB_BITS + 3), // carry_top_extra
        WitnessCell::Standard(ZeroWitnessCell::create()),
        WitnessCell::Standard(ZeroWitnessCell::create()),
    ],
    // Zero row
    [
        WitnessCell::Standard(CopyWitnessCell::create(2, 0)), // left_input_hi
        WitnessCell::Standard(CopyWitnessCell::create(4, 0)), // right_input_lo
        WitnessCell::Standard(CopyWitnessCell::create(5, 0)), // right_input_mid
        WitnessCell::Standard(CopyWitnessCell::create(6, 0)), // right_input_hi
        WitnessCell::Standard(CopyWitnessCell::create(12, 0)), // remainder_lo
        WitnessCell::Standard(CopyWitnessCell::create(13, 0)), // remainder_mid
        WitnessCell::Standard(CopyWitnessCell::create(14, 0)), // remainder_hi
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

fn init_foreign_field_mul_row<F: PrimeField>(
    witness: &mut [Vec<F>; COLUMNS],
    row: usize,
    product_mid: F,
    carry: F,
) {
    for col in 0..COLUMNS {
        match &WITNESS_SHAPE[row][col] {
            WitnessCell::Standard(standard_cell) => {
                handle_standard_witness_cell(
                    witness,
                    standard_cell,
                    row,
                    col,
                    F::zero(), /* unused by this gate */
                )
            }
            WitnessCell::Shift(shift_cell) => {
                todo!()
                // TODO: Joseph
            }
            WitnessCell::ValueLimb(value_limb_cell) => {
                witness[col][row] = value_to_limb(
                    match value_limb_cell.kind {
                        // value
                        ValueType::Carry => carry,
                        ValueType::ProductMid => product_mid,
                    },
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
    let mut witness = array_init(|_| vec![F::zero(); 0]);

    // Create multi-range-check witness for left_input and right_input
    range_check::extend_witness(&mut witness, left_input);
    range_check::extend_witness(&mut witness, right_input);

    // TODO: Compute quotient and remainder
    let product_mid = F::zero();
    let carry = F::zero();

    // Create foreign field multiplication and zero witness rows
    for w in &mut witness {
        w.extend(std::iter::repeat(F::zero()).take(2));
    }

    // ForeignFieldMul row
    init_foreign_field_mul_row(&mut witness, 20, product_mid, carry);
    // Zero row
    init_foreign_field_mul_row(&mut witness, 21, F::zero(), F::zero());

    witness
}
