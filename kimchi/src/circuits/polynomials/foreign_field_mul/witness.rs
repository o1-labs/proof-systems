//! Foreign field multiplication witness computation

use crate::circuits::{
    polynomial::COLUMNS,
    polynomials::range_check::{
        self,
        witness::{
            extend_witness, handle_standard_witness_cell, value_to_limb, CopyWitnessCell,
            ZeroWitnessCell,
        },
    },
};
use ark_ff::PrimeField;
use array_init::array_init;
use num_bigint::BigUint;
use num_integer::Integer;
use o1_utils::{
    field_helpers::{FieldFromBig, FieldHelpers},
    foreign_field::{ForeignElement, LIMB_BITS},
};

use super::circuitgates::compute_intermediate_products;

// Extend standard WitnessCell to support foreign field multiplication
// specific cell types
//
//     * Shift     := value is copied from another cell and right shifted (little-endian)
//     * ValueLimb := contiguous range of bits extracted a value
//
// TODO: Currently located in range check, but could be moved elsewhere
pub enum WitnessCell {
    Standard(range_check::witness::WitnessCell),
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
    for (row, wit) in WITNESS_SHAPE.iter().enumerate() {
        for col in 0..COLUMNS {
            match &wit[col] {
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
    extend_witness(&mut witness, left_input);
    extend_witness(&mut witness, right_input);

    // Compute quotient and remainder and add to witness
    let (quotient_big, remainder_big) =
        (left_input.to_big() * right_input.to_big()).div_rem(&foreign_modulus.to_big());

    let quotient = ForeignElement::new_from_big(quotient_big);
    let remainder = ForeignElement::new_from_big(remainder_big);
    extend_witness(&mut witness, quotient);
    extend_witness(&mut witness, remainder);

    println!("left_input: {}", left_input);
    println!("right_input: {}", right_input);
    println!("quotient: {}", quotient);
    println!("remainder: {}", remainder);

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
    println!("product_lo: {}", product_lo);
    println!("product_mi: {}", product_mi);
    println!("product_hi: {}", product_hi);

    // Define some helpers
    let product_lo_big: BigUint = product_lo.into();
    let product_mi_big: BigUint = product_mi.into();
    let product_hi_big: BigUint = product_hi.into();
    let remainder_hi_big: BigUint = (*remainder.hi()).into();
    let two_to_88: BigUint = F::from(2u128.pow(LIMB_BITS as u32)).into();
    let two_to_176 = two_to_88.clone() * two_to_88.clone();
    let (carry_bot, _) = product_lo_big.div_rem(&two_to_176);
    let (product_mi_top, product_mi_bot) = product_mi_big.div_rem(&two_to_88);
    let (_, product_mi_top_limb) = product_mi_top.div_rem(&two_to_88);
    let carry_top: BigUint = carry_bot.clone() + product_mi_top + product_hi_big - remainder_hi_big;
    let (_, carry_top_limb) = carry_top.div_rem(&two_to_88);

    let product_mi_bot = F::from_big(product_mi_bot).expect("big_f does not fit in F");
    let product_mi_top_limb = F::from_big(product_mi_top_limb).expect("big_f does not fit in F");
    let carry_top_limb = F::from_big(carry_top_limb).expect("big_f does not fit in F");

    // Define the row for the multi-range check for the product_mi_bot, product_mi_top_limb, and carry_top_limb
    extend_witness(
        &mut witness,
        ForeignElement::new([product_mi_bot, product_mi_top_limb, carry_top_limb]),
    );

    // Create foreign field multiplication and zero witness rows
    for w in &mut witness {
        w.extend(std::iter::repeat(F::zero()).take(2));
    }

    let carry_bot = F::from_big(carry_bot).expect("big_f does not fit in F");
    let carry_top = F::from_big(carry_top).expect("big_f does not fit in F");

    // ForeignFieldMul and Zero row
    init_foreign_field_mul_rows(&mut witness, 20, product_mi, carry_bot, carry_top);

    witness
}

pub fn check_witness<F: PrimeField>(
    witness: &[Vec<F>; COLUMNS],
    foreign_mod: ForeignElement<F, 3>,
) -> Result<(), String> {
    let [foreign_modulus_lo, foreign_modulus_mi, foreign_modulus_hi] = foreign_mod.limbs;

    let left_input_lo = witness[0][20];
    let left_input_mi = witness[1][20];
    let left_input_hi = witness[3][21];

    let right_input_lo = witness[1][21];
    let right_input_mi = witness[2][21];
    let right_input_hi = witness[3][21];

    let carry_shift = witness[2][20];
    let quotient_shift = witness[3][20];

    let quotient_lo = witness[4][20];
    let quotient_mi = witness[5][20];
    let quotient_hi = witness[6][20];

    let remainder_lo = witness[4][21];
    let remainder_mi = witness[5][21];
    let remainder_hi = witness[6][21];

    let product_mi_bot = witness[7][20];
    let product_mi_top_limb = witness[8][20];
    let product_mi_top_extra = witness[9][20];
    let carry_bot = witness[10][20];
    let carry_top_limb = witness[11][20];
    let carry_top_extra = witness[12][20];

    let (product_lo, product_mi, product_hi) = compute_intermediate_products(
        left_input_lo,
        left_input_mi,
        left_input_hi,
        right_input_lo,
        right_input_mi,
        right_input_hi,
        quotient_lo,
        quotient_mi,
        quotient_hi,
        foreign_modulus_lo,
        foreign_modulus_mi,
        foreign_modulus_hi,
    );

    let eight = F::from(8u32);
    let two_to_8 = F::from(2u32.pow(8));
    let two_to_9 = F::from(2u32.pow(9));
    let two_to_88 = F::from(2u128.pow(88));
    let two_to_176 = two_to_88.clone() * two_to_88.clone();

    let product_mi_top = two_to_88.clone() * product_mi_top_extra.clone() + product_mi_top_limb;
    let product_mi_sum = two_to_88.clone() * product_mi_top.clone() + product_mi_bot.clone();

    println!("middle intermediate");
    assert_eq!(F::zero(), product_mi - product_mi_sum);

    println!("carry botom");
    assert_eq!(F::zero(), crumb(&carry_bot));

    println!("mi top extra");
    assert_eq!(F::zero(), crumb(&product_mi_top_extra));

    println!("carry shift");
    assert_eq!(F::zero(), carry_shift - two_to_9 * carry_top_extra.clone());

    println!("quo shift");
    assert_eq!(F::zero(), quotient_shift - two_to_8 * quotient_hi);

    println!("zero bot");
    let zero_bot = product_lo - remainder_lo + two_to_88.clone() * (product_mi_bot - remainder_mi);
    assert_eq!(F::zero(), zero_bot - two_to_176 * carry_bot.clone());

    let carry_top = eight * carry_top_extra + carry_top_limb;
    let zero_top = carry_bot + product_mi_top + product_hi - remainder_hi;

    println!("zero top");
    assert_eq!(F::zero(), zero_top - two_to_88 * carry_top);

    Ok(())
}

pub fn crumb<F: PrimeField>(x: &F) -> F {
    x.clone() * (x.clone() - F::one()) * (x.clone() - F::from(2u64)) * (x.clone() - F::from(3u64))
}
