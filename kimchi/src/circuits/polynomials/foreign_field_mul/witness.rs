//! Foreign field multiplication witness computation

use crate::circuits::{
    expr::constraints::crumb,
    polynomial::COLUMNS,
    polynomials::range_check::{
        self,
        witness::{
            extend_witness, handle_standard_witness_cell, value_to_limb, CopyWitnessCell,
            ValueWitnessCell, ZeroWitnessCell,
        },
    },
};
use ark_ff::{Field, PrimeField};
use array_init::array_init;
use num_bigint::BigUint;
use num_integer::Integer;
use o1_utils::{
    field_helpers::FieldHelpers,
    foreign_field::{ForeignElement, LIMB_BITS},
};

// Extend standard WitnessCell to support foreign field multiplication
// specific cell types
//
//     * Shift     := value is copied from another cell and right shifted (little-endian)
//     * ValueLimb := contiguous range of bits overcted a value
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
    ProductMi,
    CarryBot,
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
        WitnessCell::Standard(CopyWitnessCell::create(2, 0)), // left_input_hi
        WitnessCell::Standard(CopyWitnessCell::create(4, 0)), // right_input_lo
        WitnessCell::Standard(CopyWitnessCell::create(5, 0)), // right_input_mi
        ShiftWitnessCell::create(20, 12, 8),                  // carry_shift from carry_top_over
        ShiftWitnessCell::create(20, 9, 9), // product_shift from product_mi_top_over
        ValueLimbWitnessCell::create(ValueType::ProductMi, 0, LIMB_BITS), // product_mi_bot
        ValueLimbWitnessCell::create(ValueType::ProductMi, LIMB_BITS, 2 * LIMB_BITS), // product_mi_top_limb
        ValueLimbWitnessCell::create(ValueType::ProductMi, 2 * LIMB_BITS, 2 * LIMB_BITS + 2), // product_mi_top_over
        ValueLimbWitnessCell::create(ValueType::CarryBot, 0, 2), // carry_bot
        ValueLimbWitnessCell::create(ValueType::CarryTop, 0, LIMB_BITS), // carry_top_limb
        ValueLimbWitnessCell::create(ValueType::CarryTop, LIMB_BITS, LIMB_BITS + 3), // carry_top_over
        WitnessCell::Standard(ZeroWitnessCell::create()),
        WitnessCell::Standard(ZeroWitnessCell::create()),
    ],
    // Zero row
    [
        WitnessCell::Standard(CopyWitnessCell::create(6, 0)), // right_input_hi
        WitnessCell::Standard(CopyWitnessCell::create(8, 0)), // quotient_lo
        WitnessCell::Standard(CopyWitnessCell::create(9, 0)), // quotient_mi
        WitnessCell::Standard(CopyWitnessCell::create(10, 0)), // quotient_hi
        WitnessCell::Standard(CopyWitnessCell::create(12, 0)), // remainder_lo
        WitnessCell::Standard(CopyWitnessCell::create(13, 0)), // remainder_mi
        WitnessCell::Standard(CopyWitnessCell::create(14, 0)), // remainder_hi
        WitnessCell::Standard(ValueWitnessCell::create(0)),   // aux_lo
        WitnessCell::Standard(ValueWitnessCell::create(1)),   // aux_mi
        WitnessCell::Standard(ValueWitnessCell::create(2)),   // aux_hi
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
    aux: [F; 3],
) {
    for (row, wit) in WITNESS_SHAPE.iter().enumerate() {
        // must go in reverse order because otherwise the shift cells will be uninitialized
        for col in (0..COLUMNS).rev() {
            match &wit[col] {
                WitnessCell::Standard(standard_cell) => {
                    handle_standard_witness_cell(witness, standard_cell, offset + row, col, &aux)
                }
                WitnessCell::Shift(shift_cell) => {
                    witness[col][offset + row] = F::from(2u32).pow([shift_cell.shift])
                        * witness[shift_cell.col][shift_cell.row];
                }
                WitnessCell::ValueLimb(value_limb_cell) => {
                    witness[col][offset + row] = value_to_limb(
                        match value_limb_cell.kind {
                            // value
                            ValueType::CarryBot => carry_bot,
                            ValueType::CarryTop => carry_top,
                            ValueType::ProductMi => product_mi,
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
    let (quotient, remainder) =
        (left_input.to_biguint() * right_input.to_biguint()).div_rem(&foreign_modulus.to_biguint());
    let quotient = ForeignElement::from_biguint(quotient);
    let remainder = ForeignElement::from_biguint(remainder);
    extend_witness(&mut witness, quotient);
    extend_witness(&mut witness, remainder);

    let two = F::from(2u32);
    let two_to_limb = two.pow(&[LIMB_BITS as u64]);
    let power_lo_top = two; // 2^{2L+1}
    let power_mi_top = two_to_limb * two * two; // 2^{2L+2}
                                                //let power_hi_top = power_mi.clone() * two.clone(); // 2^{2L+3}

    let (product_lo, product_mi, product_hi, aux_lo, aux_mi, aux_hi) =
        compute_auxiliar(left_input, right_input, quotient, foreign_modulus);

    // Define some helpers
    let product_mi_big: BigUint = product_mi.into();

    let two_to_88: F = F::from(2u128.pow(LIMB_BITS as u32));
    let two_to_88_big: BigUint = two_to_88.into();
    let two_to_176 = two_to_88_big.clone() * two_to_88_big.clone();
    let (product_mi_top, product_mi_bot) = product_mi_big.div_rem(&two_to_88_big);

    let zero_bot = product_lo - *remainder.lo()
        + two_to_88 * (F::from_biguint(product_mi_bot.clone()).unwrap() - *remainder.mi());
    let zero_bot_big: BigUint = zero_bot.into();
    let (carry_bot, _) = zero_bot_big.div_rem(&two_to_176);

    let (_, product_mi_top_limb) = product_mi_top.div_rem(&two_to_88_big);
    let zero_top: F = F::from_biguint(carry_bot.clone()).unwrap()
        + F::from_biguint(product_mi_top).unwrap()
        + product_hi
        - *remainder.hi()
        - aux_lo * power_lo_top
        - aux_mi * power_mi_top;
    let zero_top_big: BigUint = zero_top.into();
    let (carry_top_big, _) = zero_top_big.div_rem(&two_to_88_big);
    let carry_top: F = F::from_biguint(carry_top_big.clone()).unwrap();
    let (_carry_top_over, carry_top_limb) = carry_top_big.div_rem(&two_to_88_big);

    let product_mi_bot = F::from_biguint(product_mi_bot).expect("big_f does not fit in F");
    let product_mi_top_limb =
        F::from_biguint(product_mi_top_limb).expect("big_f does not fit in F");
    let carry_top_limb = F::from_biguint(carry_top_limb).expect("big_f does not fit in F");

    // Define the row for the multi-range check for the product_mi_bot, product_mi_top_limb, and carry_top_limb
    extend_witness(
        &mut witness,
        ForeignElement::create([product_mi_bot, product_mi_top_limb, carry_top_limb]),
    );

    // Create foreign field multiplication and zero witness rows
    for w in &mut witness {
        w.extend(std::iter::repeat(F::zero()).take(2));
    }

    let carry_bot = F::from_biguint(carry_bot).expect("big_f does not fit in F");

    // ForeignFieldMul and Zero row
    init_foreign_field_mul_rows(
        &mut witness,
        20,
        product_mi,
        carry_bot,
        carry_top,
        [aux_lo, aux_mi, aux_hi],
    );

    witness
}

pub fn check_witness<F: PrimeField>(
    witness: &[Vec<F>; COLUMNS],
    foreign_mod: ForeignElement<F, 3>,
) -> Result<(), String> {
    let left_input_lo = witness[0][20];
    let left_input_mi = witness[1][20];
    let left_input_hi = witness[2][20];

    let right_input_lo = witness[3][20];
    let right_input_mi = witness[4][20];
    let right_input_hi = witness[0][21];

    let carry_shift = witness[5][20];
    let product_shift = witness[6][20];

    let quotient_lo = witness[1][21];
    let quotient_mi = witness[2][21];
    let quotient_hi = witness[3][21];

    let remainder_lo = witness[4][21];
    let remainder_mi = witness[5][21];
    let remainder_hi = witness[6][21];

    let aux_lo = witness[7][21];
    let aux_mi = witness[8][21];
    let aux_hi = witness[9][21];

    let product_mi_bot = witness[7][20];
    let product_mi_top_limb = witness[8][20];
    let product_mi_top_over = witness[9][20];
    let carry_bot = witness[10][20];
    let carry_top_limb = witness[11][20];
    let carry_top_over = witness[12][20];

    let two = F::from(2u32);
    let two_to_limb = two.pow(&[LIMB_BITS as u64]);
    let power_lo_top = two; // 2^{2L+1}
    let power_mi_top = two_to_limb * two * two; // 2^
                                                //let power_hi_top = power_mi.clone() * two.clone(); // 2^{2L+3}

    let left_input = ForeignElement::create([left_input_lo, left_input_mi, left_input_hi]);
    let right_input = ForeignElement::create([right_input_lo, right_input_mi, right_input_hi]);
    let quotient = ForeignElement::create([quotient_lo, quotient_mi, quotient_hi]);
    let (product_lo, product_mi, product_hi, _aux_lo, _aux_mi, _aux_hi) =
        compute_auxiliar(left_input, right_input, quotient, foreign_mod);

    let two_to_8 = F::from(2u32.pow(8));
    let two_to_9 = F::from(2u32.pow(9));
    let two_to_88 = F::from(2u128.pow(88));
    let two_to_176 = two_to_88 * two_to_88;

    assert_eq!(F::zero(), aux_lo * (aux_lo - F::one()));
    assert_eq!(F::zero(), aux_mi * (aux_mi - F::one()));
    assert_eq!(F::zero(), aux_hi * (aux_hi - F::one()));

    let product_mi_top = two_to_88 * product_mi_top_over + product_mi_top_limb;
    let product_mi_sum = two_to_88 * product_mi_top + product_mi_bot;
    assert_eq!(F::zero(), product_mi - product_mi_sum);

    assert_eq!(F::zero(), crumb(&carry_bot));

    assert_eq!(F::zero(), crumb(&product_mi_top_over));

    assert_eq!(F::zero(), carry_shift - two_to_8 * carry_top_over);

    assert_eq!(F::zero(), product_shift - two_to_9 * product_mi_top_over);

    let zero_bot = product_lo - remainder_lo + two_to_88 * (product_mi_bot - remainder_mi);
    assert_eq!(F::zero(), zero_bot - two_to_176 * carry_bot);

    let carry_top = two_to_88 * carry_top_over + carry_top_limb;
    let zero_top = carry_bot + product_mi_top + product_hi
        - remainder_hi
        - aux_lo * power_lo_top
        - aux_mi * power_mi_top;
    assert_eq!(F::zero(), zero_top - two_to_88 * carry_top);

    Ok(())
}

/// Compute nonzero intermediate products with the bitstring format.
/// It also returns the auxiliary flags for underflows.
///
/// For details see this section of the design document
///
/// <https://hackmd.io/37M7qiTaSIKaZjCC5OnM1w?view#Intermediate-products>
///
pub fn compute_auxiliar<F: Field>(
    left_input: ForeignElement<F, 3>,
    right_input: ForeignElement<F, 3>,
    quotient: ForeignElement<F, 3>,
    foreign_modulus: ForeignElement<F, 3>,
) -> (F, F, F, F, F, F) {
    let [left_input_lo, left_input_mi, left_input_hi] = left_input.limbs;
    let [right_input_lo, right_input_mi, right_input_hi] = right_input.limbs;
    let [quotient_lo, quotient_mi, quotient_hi] = quotient.limbs;
    let [foreign_modulus_lo, foreign_modulus_mi, foreign_modulus_hi] = foreign_modulus.limbs;

    let two = F::from(2u32);
    let two_to_limb = two.pow(&[LIMB_BITS as u64]);
    let power_lo = two_to_limb * two_to_limb * two; // 2^{2L+1}
    let power_mi = power_lo * two; // 2^{2L+2}
    let power_hi = power_mi * two; // 2^{2L+3}

    let mut aux_lo = F::zero();
    let mut aux_mi = F::zero();
    let mut aux_hi = F::zero();

    let add_lo = left_input_lo * right_input_lo;
    let sub_lo = quotient_lo * foreign_modulus_lo;
    if add_lo < sub_lo {
        aux_lo = F::one();
    }
    let add_mi = left_input_lo * right_input_mi + left_input_mi * right_input_lo;
    let sub_mi = quotient_lo * foreign_modulus_mi + quotient_mi * foreign_modulus_lo;
    if add_mi < sub_mi {
        aux_mi = F::one();
    }
    let add_hi = left_input_lo * right_input_hi
        + left_input_hi * right_input_lo
        + left_input_mi * right_input_mi;
    let sub_hi = quotient_lo * foreign_modulus_hi
        + quotient_hi * foreign_modulus_lo
        + quotient_mi * foreign_modulus_mi;
    if add_hi < sub_hi {
        aux_hi = F::one();
    }

    let product_lo = add_lo - sub_lo + aux_lo * power_lo;
    let product_mi = add_mi - sub_mi + aux_mi * power_mi;
    let product_hi = add_hi - sub_hi + aux_hi * power_hi;

    (product_lo, product_mi, product_hi, aux_lo, aux_mi, aux_hi)
}
