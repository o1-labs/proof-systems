use crate::circuits::{
    polynomial::COLUMNS,
    polynomials::range_check::{
        self,
        witness::{extend_witness, handle_standard_witness_cell, CopyWitnessCell, ZeroWitnessCell},
    },
};
use ark_ff::{Field, PrimeField};
use num_bigint::BigUint;
use o1_utils::foreign_field::{ForeignElement, LIMB_BITS};
use std::array;

fn compute_bound_values<F: PrimeField>(
    result: &ForeignElement<F, 3>,
    modulus: &ForeignElement<F, 3>,
) -> (ForeignElement<F, 3>, F, F) {
    let two_to_limb = 2u128.pow(88);
    let max = BigUint::from(two_to_limb).pow(3);
    let big_mod = modulus.to_big();
    let bound = result.to_big() + max - big_mod.clone();
    let bound_limbs = ForeignElement::<F, 3>::from_big(bound);
    let carry_mi = *bound_limbs.hi() - *result.hi() + *modulus.hi() - F::from(two_to_limb);
    let carry_lo =
        *bound_limbs.mi() - *result.mi() + *modulus.mi() + carry_mi * F::from(two_to_limb);

    (bound_limbs, carry_lo, carry_mi)
}

fn compute_subadd_values<F: PrimeField>(
    left_input: &ForeignElement<F, 3>,
    right_input: &ForeignElement<F, 3>,
    add: bool,
    foreign_modulus: &ForeignElement<F, 3>,
) -> (ForeignElement<F, 3>, F, F, F, F) {
    let two_to_limb = F::from(2u128.pow(LIMB_BITS as u32));

    // Compute bigint version of the inputs
    let left = left_input.to_big();
    let right = right_input.to_big();

    let modulus = foreign_modulus.to_big();

    if add {
        // addition
        let sig = F::one();
        let sum = left + right;
        let overflows = sum >= modulus;
        let ovf = if overflows { F::one() } else { F::zero() };
        let out = if overflows {
            sum - modulus.clone()
        } else {
            sum
        };
        let out_limbs = ForeignElement::from_big(out);
        let carry_mi =
            *out_limbs.hi() - *left_input.hi() - *right_input.hi() + ovf * *foreign_modulus.hi();
        let carry_lo = *out_limbs.mi() - *left_input.mi() - *right_input.mi()
            + ovf * *foreign_modulus.mi()
            + two_to_limb * carry_mi;
        (out_limbs, sig, ovf, carry_lo, carry_mi)
    } else {
        // subtraction
        let sig = -F::one();
        let overflows = left < right;
        let ovf = if overflows { -F::one() } else { F::zero() };
        let out = if overflows {
            modulus.clone() + left - right
        } else {
            left - right
        };
        let out_limbs = ForeignElement::from_big(out);
        let carry_mi =
            *out_limbs.hi() - *left_input.hi() + right_input.limbs[2] + ovf * *foreign_modulus.hi();
        let carry_lo = *out_limbs.mi() - *left_input.mi()
            + right_input.limbs[1]
            + ovf * *foreign_modulus.mi()
            + two_to_limb * carry_mi;
        (out_limbs, sig, ovf, carry_lo, carry_mi)
    }
}

/// Creates a FFAdd witness
/// opcode = true for subtraction, false for addition
pub fn create_witness<F: PrimeField>(
    inputs: Vec<BigUint>,
    opcode: Vec<bool>,
    modulus: BigUint,
) -> [Vec<F>; COLUMNS] {
    let num = inputs.len() - 1; // number of chained additions

    /*ensure_eq!(
        opcode.len(),
        num,
        "The number of inputs does not correspond with the number of operations"
    );*/

    let mut witness = array::from_fn(|_| vec![F::zero(); 0]);

    let foreign_modulus = ForeignElement::from_big(modulus.clone());

    // Create multi-range-check witness for first left input
    let mut left = ForeignElement::from_big(inputs[0].clone());
    extend_witness(&mut witness, left.clone());
    let mut add_values: Vec<(F, F, F, F)> = vec![];
    for i in 0..num {
        let right = ForeignElement::from_big(inputs[i + 1].clone());
        let (out, sig, ovf, carry_lo, carry_mi) =
            compute_subadd_values(&left, &right, opcode[i], &foreign_modulus);
        // Create multi-range-check witness for right_input (left_input was done in previous iteration) and output
        extend_witness(&mut witness, right.clone());
        extend_witness(&mut witness, out.clone());

        add_values.append(&mut vec![(sig, ovf, carry_lo, carry_mi)]);
        left = out; // output
    }

    // Compute values for final bound check, needs a 4 limb right input
    let (bound, bound_carry_lo, bound_carry_mi) = compute_bound_values(&left, &foreign_modulus);

    // Final RangeCheck for bound
    extend_witness(&mut witness, bound);
    let mut offset = witness[0].len(); // number of witness rows of the gadget before the first row of the addition gate

    // Include FFAdd and FFFin and Zero gates

    for i in 0..num {
        // Create foreign field addition row
        for w in &mut witness {
            w.extend(std::iter::repeat(F::zero()).take(1));
        }

        // ForeignFieldAdd row and Zero row
        init_foreign_field_add_rows(
            &mut witness,
            offset,
            i,
            add_values[i].0,
            add_values[i].1,
            [add_values[i].2, add_values[i].3],
        );
        offset += 1;
    }

    for w in &mut witness {
        w.extend(std::iter::repeat(F::zero()).take(1));
    }
    init_foreign_field_fin_rows(&mut witness, offset, num, [bound_carry_lo, bound_carry_mi]);

    witness
}

// ==================
// WITNESS CELL CODE
// ==================

// Extend standard WitnessCell to support foreign field addition
// specific cell types
//
//     * ValueLimb := contiguous range of bits extracted a value
//
// TODO: Currently located in range check, but could be moved elsewhere
pub enum WitnessCell<F: Field> {
    Standard(range_check::witness::WitnessCell),
    FieldElem(FieldElemWitnessCell),
    Constant(F),
    Ignore,
}

// Witness cell containing a type of value that is a field element
pub enum FieldElemType {
    Overflow,
    Carry,
    Sign,
}

#[derive(Copy, Clone)]
pub enum FieldElemOrder {
    No = -1,
    Lo = 0,
    Mi = 1,
    Hi = 2,
}

pub struct FieldElemWitnessCell {
    pub kind: FieldElemType,
    pub order: FieldElemOrder,
}

impl FieldElemWitnessCell {
    pub const fn create<F: Field>(kind: FieldElemType, order: FieldElemOrder) -> WitnessCell<F> {
        WitnessCell::FieldElem(FieldElemWitnessCell { kind, order })
    }
}

fn init_foreign_field_add_rows<F: PrimeField>(
    witness: &mut [Vec<F>; COLUMNS],
    offset: usize,
    index: usize,
    sign: F,
    overflow: F,
    carry: [F; 2],
) {
    let left_row = 8 * index;
    let right_row = 8 * index + 4;
    let witness_shape: [[WitnessCell<F>; COLUMNS]; 1] = [
        // ForeignFieldAdd row
        [
            WitnessCell::Standard(CopyWitnessCell::create(left_row, 0)), // left_input_lo
            WitnessCell::Standard(CopyWitnessCell::create(left_row + 1, 0)), // left_input_mi
            WitnessCell::Standard(CopyWitnessCell::create(left_row + 2, 0)), // left_input_hi
            WitnessCell::Standard(CopyWitnessCell::create(right_row, 0)), // right_input_lo
            WitnessCell::Standard(CopyWitnessCell::create(right_row + 1, 0)), // right_input_mi
            WitnessCell::Standard(CopyWitnessCell::create(right_row + 2, 0)), // right_input_hi
            FieldElemWitnessCell::create(FieldElemType::Overflow, FieldElemOrder::No), // field_overflow
            FieldElemWitnessCell::create(FieldElemType::Carry, FieldElemOrder::Lo),    // carry_lo
            FieldElemWitnessCell::create(FieldElemType::Carry, FieldElemOrder::Mi),    // carry_mi
            FieldElemWitnessCell::create(FieldElemType::Sign, FieldElemOrder::No),     // sign
            WitnessCell::Standard(ZeroWitnessCell::create()),
            WitnessCell::Standard(ZeroWitnessCell::create()),
            WitnessCell::Standard(ZeroWitnessCell::create()),
            WitnessCell::Standard(ZeroWitnessCell::create()),
            WitnessCell::Standard(ZeroWitnessCell::create()),
        ],
    ];

    for (row, wit) in witness_shape.iter().enumerate() {
        for col in 0..COLUMNS {
            handle_ffadd_rows(witness, &wit[col], row, col, offset, sign, overflow, carry);
        }
    }
}

fn init_foreign_field_fin_rows<F: PrimeField>(
    witness: &mut [Vec<F>; COLUMNS],
    offset: usize,
    num: usize,
    carry: [F; 2],
) {
    let out_row = 8 * num; // row where the final result is stored in RC
    let bound_row = 8 * num + 4; // row where the final bound is stored in RC
    let witness_shape: [WitnessCell<F>; COLUMNS] = [
        // ForeignFieldFin row
        WitnessCell::Standard(CopyWitnessCell::create(out_row, 0)), // result_lo
        WitnessCell::Standard(CopyWitnessCell::create(out_row + 1, 0)), // result_mi
        WitnessCell::Standard(CopyWitnessCell::create(out_row + 2, 0)), // result_hi
        WitnessCell::Standard(CopyWitnessCell::create(bound_row, 0)), // bound_lo
        WitnessCell::Standard(CopyWitnessCell::create(bound_row + 1, 0)), // bound_mi
        WitnessCell::Standard(CopyWitnessCell::create(bound_row + 2, 0)), // bound_hi
        WitnessCell::Standard(ZeroWitnessCell::create()),
        FieldElemWitnessCell::create(FieldElemType::Carry, FieldElemOrder::Lo), // carry_lo
        FieldElemWitnessCell::create(FieldElemType::Carry, FieldElemOrder::Mi), // carry_mi
        WitnessCell::Standard(ZeroWitnessCell::create()),
        WitnessCell::Standard(ZeroWitnessCell::create()),
        WitnessCell::Standard(ZeroWitnessCell::create()),
        WitnessCell::Standard(ZeroWitnessCell::create()),
        WitnessCell::Standard(ZeroWitnessCell::create()),
        WitnessCell::Standard(ZeroWitnessCell::create()),
    ];

    for col in 0..COLUMNS {
        handle_ffadd_rows(
            witness,
            &witness_shape[col],
            0,
            col,
            offset,
            F::zero(),
            F::zero(),
            carry,
        );
    }
}

fn handle_ffadd_rows<F: PrimeField>(
    witness: &mut [Vec<F>; COLUMNS],
    witness_cell: &WitnessCell<F>,
    row: usize,
    col: usize,
    offset: usize,
    sign: F,
    overflow: F,
    carry: [F; 2],
) {
    match witness_cell {
        WitnessCell::Standard(standard_cell) => {
            handle_standard_witness_cell(
                witness,
                standard_cell,
                offset + row,
                col,
                F::zero(), /* unused by this gate */
            )
        }
        WitnessCell::FieldElem(elem_cell) => {
            witness[col][offset + row] = {
                match elem_cell.kind {
                    FieldElemType::Overflow => overflow,
                    FieldElemType::Carry => carry[elem_cell.order as usize],
                    FieldElemType::Sign => sign,
                }
            }
        }
        WitnessCell::Constant(field_elem) => witness[col][offset + row] = *field_elem,
        WitnessCell::Ignore => (),
    }
}
