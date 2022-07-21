//! Foreign field multiplication witness computation

use crate::circuits::{
    polynomial::COLUMNS,
    polynomials::range_check::{
        self, handle_standard_witness_cell, value_to_limb, CopyWitnessCell, ZeroWitnessCell,
    },
};
use ark_ff::PrimeField;
use array_init::array_init;
use num_integer::Integer;
use o1_utils::{
    foreign_field::{ForeignElement, LIMB_BITS},
    FieldHelpers,
};

use super::compute_intermediate_products;

// Extend standard WitnessCell to support foreign field multiplication
// specific cell types
//
//     * Shift     := value is copied from another cell and right shifted (little-endian)
//     * ValueLimb := contiguous range of bits extracted a value
//
// TODO: Currently located in range check, but could be moved elsewhere
pub enum WitnessCell {
    Standard(range_check::WitnessCell),
    Shift(ShiftWitnessCell),
    ValueLimb(ValueLimbWitnessCell),
}

// Witness cell copied and shifted from another
pub struct ShiftWitnessCell {
    row: usize,
    col: usize,
    shift: u64,
}

impl ShiftWitnessCell {
    pub const fn create(row: usize, col: usize, shift: u64) -> WitnessCell {
        WitnessCell::Shift(ShiftWitnessCell { row, col, shift })
    }
}

// Witness cell containing a limb of a value
pub enum ValueType {
    ProductMid,
    CarryBottom,
    CarryTop,
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
        WitnessCell::Standard(CopyWitnessCell::create(1, 0)), // left_input_mi
        ShiftWitnessCell::create(20, 0, 9),                   // carry_shift
        ShiftWitnessCell::create(10, 0, 8),                   // quotient_shift
        WitnessCell::Standard(CopyWitnessCell::create(8, 0)), // quotient_lo
        WitnessCell::Standard(CopyWitnessCell::create(9, 0)), // quotient_mi
        WitnessCell::Standard(CopyWitnessCell::create(10, 0)), // quotient_hi
        ValueLimbWitnessCell::create(ValueType::ProductMid, 0, LIMB_BITS), // product_mi_bot
        ValueLimbWitnessCell::create(ValueType::ProductMid, LIMB_BITS, 2 * LIMB_BITS), // product_mi_top_limb
        ValueLimbWitnessCell::create(ValueType::ProductMid, 2 * LIMB_BITS, 2 * LIMB_BITS + 2), // product_mi_top_extra
        ValueLimbWitnessCell::create(ValueType::CarryBottom, 0, 2), // carry_bot
        ValueLimbWitnessCell::create(ValueType::CarryTop, 0, LIMB_BITS), // carry_top_limb
        ValueLimbWitnessCell::create(ValueType::CarryTop, LIMB_BITS, LIMB_BITS + 3), // carry_top_extra
        WitnessCell::Standard(ZeroWitnessCell::create()),
        WitnessCell::Standard(ZeroWitnessCell::create()),
    ],
    // Zero row
    [
        WitnessCell::Standard(CopyWitnessCell::create(2, 0)), // left_input_hi
        WitnessCell::Standard(CopyWitnessCell::create(4, 0)), // right_input_lo
        WitnessCell::Standard(CopyWitnessCell::create(5, 0)), // right_input_mi
        WitnessCell::Standard(CopyWitnessCell::create(6, 0)), // right_input_hi
        WitnessCell::Standard(CopyWitnessCell::create(12, 0)), // remainder_lo
        WitnessCell::Standard(CopyWitnessCell::create(13, 0)), // remainder_mi
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

fn init_foreign_field_mul_rows<F: PrimeField>(
    witness: &mut [Vec<F>; COLUMNS],
    offset: usize,
    product_mi: F,
    carry_bot: F,
    carry_top: F,
) {
    for row in 0..2 {
        for col in 0..COLUMNS {
            match &WITNESS_SHAPE[row][col] {
                WitnessCell::Standard(standard_cell) => {
                    handle_standard_witness_cell(
                        witness,
                        standard_cell,
                        offset + row,
                        col,
                        F::zero(), /* unused by this gate */
                    )
                }
                WitnessCell::Shift(shift_cell) => {
                    witness[col][offset + row] = F::from(2u32).pow([shift_cell.shift])
                        * witness[shift_cell.col][shift_cell.row];
                }
                WitnessCell::ValueLimb(value_limb_cell) => {
                    witness[col][row] = value_to_limb(
                        match value_limb_cell.kind {
                            // value
                            ValueType::CarryBottom => carry_bot,
                            ValueType::CarryTop => carry_top,
                            ValueType::ProductMid => product_mi,
                        },
                        value_limb_cell.start, // starting bit
                        value_limb_cell.end,   // ending bit (exclusive)
                    );
                }
            }
        }
    }
}

/// Create a foreign field multiplication witness
/// Input: multiplicands left_input and right_input
pub fn create_witness<F: PrimeField>(
    left_input: ForeignElement<F, 3>,
    right_input: ForeignElement<F, 3>,
    foreign_modulus: ForeignElement<F, 3>,
) -> [Vec<F>; COLUMNS] {
    let mut witness = array_init(|_| vec![F::zero(); 0]);

    // Create multi-range-check witness for left_input and right_input
    range_check::extend_witness(&mut witness, left_input);
    range_check::extend_witness(&mut witness, right_input);

    // Compute quotient and remainder and add to witness
    let (quotient_big, remainder_big) =
        (left_input.to_big() * right_input.to_big()).div_rem(&foreign_modulus.to_big());
    let quotient = ForeignElement::new_from_big(quotient_big);
    let remainder = ForeignElement::new_from_big(remainder_big);
    range_check::extend_witness(&mut witness, quotient);
    range_check::extend_witness(&mut witness, remainder);

    // Compute nonzero intermediate products (uses the same code as constraints!)
    let (product_lo, product_mi, product_hi) = compute_intermediate_products(
        *left_input.lo(),
        *left_input.mi(),
        *left_input.hi(),
        *right_input.lo(),
        *right_input.mi(),
        *right_input.hi(),
        *quotient.lo(),
        *quotient.mi(),
        *quotient.hi(),
        *foreign_modulus.lo(),
        *foreign_modulus.mi(),
        *foreign_modulus.hi(),
    );

    // Define some helpers
    let two_to_88 = F::from(2u128.pow(LIMB_BITS as u32)).to_big();
    let two_to_176 = two_to_88.clone() * two_to_88.clone();
    let (carry_bot, _) = product_lo.to_big().div_rem(&two_to_176);
    let (product_mi_top, product_mi_bot) = product_mi.to_big().div_rem(&two_to_88);
    let (_, product_mi_top_limb) = product_mi_top.div_rem(&two_to_88);
    let carry_top =
        carry_bot.clone() + product_mi_top + product_hi.to_big() - remainder.hi().to_big();
    let (_, carry_top_limb) = carry_top.div_rem(&two_to_88);

    let product_mi_bot = F::from_big(product_mi_bot).expect("BigUint does not fit in F");
    let product_mi_top_limb = F::from_big(product_mi_top_limb).expect("BigUint does not fit in F");
    let carry_top_limb = F::from_big(carry_top_limb).expect("BigUint does not fit in F");

    // Define the row for the multi-range check for the product_mi_bot, product_mi_top_limb, and carry_top_limb
    range_check::extend_witness(
        &mut witness,
        ForeignElement::new([product_mi_bot, product_mi_top_limb, carry_top_limb]),
    );

    // Create foreign field multiplication and zero witness rows
    for w in &mut witness {
        w.extend(std::iter::repeat(F::zero()).take(2));
    }

    let carry_bot = F::from_big(carry_bot).expect("BigUint does not fit in F");
    let carry_top = F::from_big(carry_top).expect("BigUint does not fit in F");

    // ForeignFieldMul and Zero row
    init_foreign_field_mul_rows(&mut witness, 20, product_mi, carry_bot, carry_top);

    witness
}
