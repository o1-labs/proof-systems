//! Foreign field multiplication witness computation

use crate::circuits::{
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
use num_bigint::{BigInt, BigUint, ToBigInt};
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
    let (quotient_big, remainder_big) =
        (left_input.to_big() * right_input.to_big()).div_rem(&foreign_modulus.to_big());

    let quotient = ForeignElement::new_from_big(quotient_big);
    let remainder = ForeignElement::new_from_big(remainder_big);
    extend_witness(&mut witness, quotient);
    extend_witness(&mut witness, remainder);

    println!("left:   {:02X?}", left_input.to_big().to_bytes_be());
    println!("right:  {:02X?}", right_input.to_big().to_bytes_be());
    println!("formod: {:02X?}", foreign_modulus.to_big().to_bytes_be());
    println!("quot:   {:02X?}", quotient.to_big().to_bytes_be());
    println!("rem:    {:02X?}", remainder.to_big().to_bytes_be());

    /*
        // checking bigint
        {
            let foreign_modulus_lo = <F as PrimeField>::into_repr(&foreign_modulus.lo());
            let foreign_modulus_mi = <F as PrimeField>::into_repr(&foreign_modulus.mi());
            let foreign_modulus_hi = <F as PrimeField>::into_repr(&foreign_modulus.hi());
            let left_input_lo = <F as PrimeField>::into_repr(&left_input.lo());
            let left_input_mi = <F as PrimeField>::into_repr(&left_input.mi());
            let left_input_hi = <F as PrimeField>::into_repr(&left_input.hi());
            let right_input_lo = <F as PrimeField>::into_repr(&right_input.lo());
            let right_input_mi = <F as PrimeField>::into_repr(&right_input.mi());
            let right_input_hi = <F as PrimeField>::into_repr(&right_input.hi());
            let quotient_lo = <F as PrimeField>::into_repr(&quotient.lo());
            let quotient_mi = <F as PrimeField>::into_repr(&quotient.mi());
            let quotient_hi = <F as PrimeField>::into_repr(&quotient.hi());
            let remainder_lo = <F as PrimeField>::into_repr(&remainder.lo());
            let remainder_mi = <F as PrimeField>::into_repr(&remainder.mi());
            let remainder_hi = <F as PrimeField>::into_repr(&remainder.hi());

            let product_lo = left_input_lo.clone() * right_input_lo.clone()
                - quotient_lo.clone() * foreign_modulus_lo.clone();
            let product_mi = left_input_lo.clone() * right_input_mi.clone()
                + left_input_mi.clone() * right_input_lo.clone()
                - quotient_lo.clone() * foreign_modulus_mi.clone()
                - quotient_mi.clone() * foreign_modulus_lo.clone();
            let product_hi = left_input_lo * right_input_hi
                + left_input_hi.clone() * right_input_lo.clone()
                + left_input_mi.clone() * right_input_mi.clone()
                - quotient_lo.clone() * foreign_modulus_hi.clone()
                - quotient_hi.clone() * foreign_modulus_lo.clone()
                - quotient_mi.clone() * foreign_modulus_mi.clone();
        }
    */
    // Compute nonzero intermediate products (uses the same code as constraints!)
    /*let (product_lo, product_mi, product_hi) = compute_intermediate_products(
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
    */

    let two = F::from(2u32);
    let two_to_limb = two.pow(&[LIMB_BITS as u64]);
    let power_lo_top = two.clone(); // 2^{2L+1}
    let power_mi_top = two_to_limb.clone() * two.clone() * two.clone(); // 2^{2L+2}
                                                                        //let power_hi_top = power_mi.clone() * two.clone(); // 2^{2L+3}

    let (product_lo, product_mi, product_hi, aux_lo, aux_mi, aux_hi) =
        compute_auxiliar(left_input, right_input, quotient, foreign_modulus);

    println!("creating witness");
    println!("product_mi: {:?}", product_mi.to_hex());
    // Define some helpers
    let product_mi_big: BigUint = product_mi.into();

    let two_to_88: F = F::from(2u128.pow(LIMB_BITS as u32));
    let two_to_88_big: BigUint = two_to_88.into();
    let two_to_176 = two_to_88_big.clone() * two_to_88_big.clone();
    let (product_mi_top, product_mi_bot) = product_mi_big.div_rem(&two_to_88_big.clone());

    let zero_bot = product_lo - *remainder.lo()
        + two_to_88 * (F::from_big(product_mi_bot.clone()).unwrap() - *remainder.mi());
    let zero_bot_big: BigUint = zero_bot.into();
    println!("zero_bot: {:?}", zero_bot.to_hex());
    let (carry_bot, _) = zero_bot_big.div_rem(&two_to_176);
    println!(
        "carry_bot: {:?}",
        F::from_big(carry_bot.clone()).unwrap().to_hex()
    );
    let (_, product_mi_top_limb) = product_mi_top.div_rem(&two_to_88_big.clone());
    let zero_top: F = F::from_big(carry_bot.clone()).unwrap()
        + F::from_big(product_mi_top.clone()).unwrap()
        + product_hi
        - *remainder.hi()
        - aux_lo * power_lo_top
        - aux_mi * power_mi_top;
    let zero_top_big: BigUint = zero_top.into();
    println!("zero_top: {:?}", zero_top.to_hex());
    let (carry_top_big, _) = zero_top_big.div_rem(&two_to_88_big.clone());
    let carry_top: F = F::from_big(carry_top_big.clone()).unwrap();
    let (_carry_top_over, carry_top_limb) = carry_top_big.div_rem(&two_to_88_big.clone());

    let product_mi_bot = F::from_big(product_mi_bot).expect("big_f does not fit in F");
    let product_mi_top_limb = F::from_big(product_mi_top_limb).expect("big_f does not fit in F");
    let carry_top_limb = F::from_big(carry_top_limb).expect("big_f does not fit in F");

    let xy_term = *left_input.mi() * *right_input.hi() + *left_input.hi() * *right_input.mi()
        - *quotient.mi() * *foreign_modulus.hi()
        - *quotient.hi() * *foreign_modulus.mi();
    let y2_term = *left_input.hi() * *right_input.hi() - *quotient.hi() * *foreign_modulus.hi();
    println!("xy_term:    {:?}", xy_term.to_hex());
    println!("y2_term:    {:?}", y2_term.to_hex());

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

    // ForeignFieldMul and Zero row
    init_foreign_field_mul_rows(
        &mut witness,
        20,
        product_mi,
        carry_bot,
        carry_top,
        [aux_lo, aux_mi, aux_hi],
    );

    view(&witness);
    witness
}

fn view<F: PrimeField>(witness: &[Vec<F>; COLUMNS]) {
    let rows = witness[0].len();
    for row in 20..rows {
        for col in 0..COLUMNS {
            println!("row {}, col{}: {:?}", row, col, witness[col][row].to_hex());
        }
        println!();
    }
}

pub fn check_witness<F: PrimeField>(
    witness: &[Vec<F>; COLUMNS],
    foreign_mod: ForeignElement<F, 3>,
) -> Result<(), String> {
    let [foreign_modulus_lo, foreign_modulus_mi, foreign_modulus_hi] = foreign_mod.limbs;

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
    let power_lo_top = two.clone(); // 2^{2L+1}
    let power_mi_top = two_to_limb.clone() * two.clone() * two.clone(); // 2^
                                                                        //let power_hi_top = power_mi.clone() * two.clone(); // 2^{2L+3}

    let left_input = ForeignElement::new([left_input_lo, left_input_mi, left_input_hi]);
    let right_input = ForeignElement::new([right_input_lo, right_input_mi, right_input_hi]);
    let quotient = ForeignElement::new([quotient_lo, quotient_mi, quotient_hi]);
    let (product_lo, product_mi, product_hi, _aux_lo, _aux_mi, _aux_hi) =
        compute_auxiliar(left_input, right_input, quotient, foreign_mod);

    let two_to_8 = F::from(2u32.pow(8));
    let two_to_9 = F::from(2u32.pow(9));
    let two_to_88 = F::from(2u128.pow(88));
    let two_to_176 = two_to_88.clone() * two_to_88.clone();

    println!("CHECK product mi");
    let product_mi_top = two_to_88.clone() * product_mi_top_over.clone() + product_mi_top_limb;
    let product_mi_sum = two_to_88.clone() * product_mi_top.clone() + product_mi_bot.clone();
    println!("product_mi:     {:?}", product_mi.to_hex());
    println!("product_mi_sum: {:?}", product_mi_sum.to_hex());
    println!("quotient_lo:    {:?}", quotient_lo.to_bytes().reverse());
    println!("quotient_mi:    {:?}", quotient_mi.to_bytes().reverse());
    println!(
        "foreign_mod_lo: {:?}",
        foreign_modulus_lo.to_bytes().reverse()
    );
    println!(
        "foreign_mod_mi: {:?}",
        foreign_modulus_mi.to_bytes().reverse()
    );
    assert_eq!(F::zero(), product_mi - product_mi_sum);

    println!("CHECK crumb carry bot");
    assert_eq!(F::zero(), crumb(&carry_bot));

    println!("CHECK crumb product mi top over");
    assert_eq!(F::zero(), crumb(&product_mi_top_over));

    println!("CHECK carry shift");
    assert_eq!(F::zero(), carry_shift - two_to_8 * carry_top_over.clone());

    println!("CHECK product shift");
    assert_eq!(F::zero(), product_shift - two_to_9 * product_mi_top_over);

    println!("CHECK zero bot");
    let zero_bot = product_lo - remainder_lo + two_to_88.clone() * (product_mi_bot - remainder_mi);
    let two_to_264 = two_to_88.clone() * two_to_176.clone();
    let two_to_352 = two_to_88.clone() * two_to_264.clone();
    let xy_term = left_input_mi * right_input_hi + left_input_hi * right_input_mi
        - quotient_mi * foreign_modulus_hi
        - quotient_hi * foreign_modulus_mi;
    let y2_term = left_input_hi * right_input_hi - quotient_hi * foreign_modulus_hi;
    let y2xy = two_to_264 * xy_term + two_to_352 * y2_term;
    let y2xy_zero = zero_bot.clone() + y2xy;
    println!("aux_lo:         {:?}", aux_lo.to_hex());
    println!("aux_mi:         {:?}", aux_mi.to_hex());
    println!("aux_hi:         {:?}", aux_hi.to_hex());
    println!("zero_bot:       {:?}", zero_bot.to_hex());
    println!("xy_term:        {:?}", xy_term.to_hex());
    println!("y2_term:        {:?}", y2_term.to_hex());
    println!("y2xy:           {:?}", y2xy.to_hex());
    println!("y2xy_zero:      {:?}", y2xy_zero.to_hex());
    println!("product_lo:     {:?}", product_lo.to_hex());
    println!("remainder_lo:   {:?}", remainder_lo.to_hex());
    println!("product_mi_bot: {:?}", product_mi_bot.to_hex());
    println!("remainder_mi:   {:?}", remainder_mi.to_hex());
    let subtraction = zero_bot - two_to_176 * carry_bot.clone();
    println!("subtraction:    {:?}", subtraction.to_hex());
    assert_eq!(F::zero(), subtraction);

    println!("CHECK zero top");
    let carry_top = two_to_88.clone() * carry_top_over + carry_top_limb;
    let zero_top = carry_bot + product_mi_top + product_hi
        - remainder_hi
        - aux_lo * power_lo_top
        - aux_mi * power_mi_top;
    println!("carry_top:      {:?}", carry_top.to_hex());
    println!("zero_top:       {:?}", zero_top.to_hex());
    println!(
        "two88*carrytop: {:?}",
        (two_to_88.clone() * carry_top.clone()).to_hex()
    );
    assert_eq!(F::zero(), zero_top - two_to_88 * carry_top);

    Ok(())
}

pub fn crumb<F: PrimeField>(x: &F) -> F {
    x.clone() * (x.clone() - F::one()) * (x.clone() - F::from(2u64)) * (x.clone() - F::from(3u64))
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
    let power_lo = two_to_limb.clone() * two_to_limb.clone() * two.clone(); // 2^{2L+1}
    let power_mi = power_lo.clone() * two.clone(); // 2^{2L+2}
    let power_hi = power_mi.clone() * two.clone(); // 2^{2L+3}

    let mut aux_lo = F::zero();
    let mut aux_mi = F::zero();
    let mut aux_hi = F::zero();

    let add_lo = left_input_lo.clone() * right_input_lo.clone();
    let sub_lo = quotient_lo.clone() * foreign_modulus_lo.clone();
    if add_lo < sub_lo {
        aux_lo = F::one();
    }
    let add_mi = left_input_lo.clone() * right_input_mi.clone()
        + left_input_mi.clone() * right_input_lo.clone();
    let sub_mi = quotient_lo.clone() * foreign_modulus_mi.clone()
        + quotient_mi.clone() * foreign_modulus_lo.clone();
    if add_mi < sub_mi {
        aux_mi = F::one();
    }
    let add_hi = left_input_lo * right_input_hi
        + left_input_hi * right_input_lo
        + left_input_mi * right_input_mi;
    let sub_hi = quotient_lo * foreign_modulus_hi.clone()
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
