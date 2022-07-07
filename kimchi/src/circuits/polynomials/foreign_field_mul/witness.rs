//! Foreign field multiplication witness computation

use ark_ff::PrimeField;
use array_init::array_init;

use crate::circuits::{
    polynomial::COLUMNS,
    polynomials::range_check::{
        self, handle_standard_witness_cell, CopyWitnessCell, LimbWitnessCell, ZeroWitnessCell,
    },
};

use ark_ec::AffineCurve;
use mina_curves::pasta::pallas;
type PallasField = <pallas::Affine as AffineCurve>::BaseField;

// Extend standard WitnessCell to support foreign field multiplication
// specific cell types
//
//     * Shift     := value is copied from another cell and right shifted (little-endian)
//     * ValueLimb := contiguous range of bits extracted from value passed as argument
//
// TODO: Currently located in range check, but could be moved
//       elsewhere so other gates could reuse
pub enum WitnessCell<F> {
    Standard(range_check::WitnessCell),
    Shift(ShiftWitnessCell),
    ValueLimb(ValueLimbWitnessCell<F>),
}

// Witness cell copied and shifted from another
pub struct ShiftWitnessCell {
    row: usize,
    col: usize,
    shift: usize,
}

impl ShiftWitnessCell {
    pub const fn create<F>(row: usize, col: usize, shift: usize) -> WitnessCell<F> {
        WitnessCell::Shift(ShiftWitnessCell { row, col, shift })
    }
}

// Witness cell containing a limb of a value
pub struct ValueLimbWitnessCell<F> {
    value: F,
    start: usize,
    end: usize,
}

impl<F> ValueLimbWitnessCell<F> {
    pub const fn create(value: F, start: usize, end: usize) -> WitnessCell<F> {
        WitnessCell::ValueLimb(ValueLimbWitnessCell { value, start, end })
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
const WITNESS_SHAPE: [[WitnessCell<PallasField>; COLUMNS]; 2] = [
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
        WitnessCell::Standard(LimbWitnessCell::create(8, 0, 86, 88)), // quotient_lo
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
                todo!()
                // TODO: Anais
            }
        }
    }
}

/// Create a foreign field multiplication witness
/// Input: three values: v0, v1 and v2
pub fn create_witness<F: PrimeField>(left_input: F, right_input: F) -> [Vec<F>; COLUMNS] {
    let mut witness: [Vec<F>; COLUMNS] = array_init(|_| vec![F::zero(); 21]);

    // Joseph: TODO

    witness
}
