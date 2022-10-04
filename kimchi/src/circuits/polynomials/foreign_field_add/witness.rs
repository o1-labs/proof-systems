//! This module computes the witness of a foreign field addition circuit.

use crate::circuits::{
    polynomial::COLUMNS,
    polynomials::range_check::{
        self,
        witness::{extend_witness, handle_standard_witness_cell, CopyWitnessCell, ZeroWitnessCell},
    },
};
use ark_ff::{Field, PrimeField};
use num_bigint::BigUint;
use o1_utils::foreign_field::{ForeignElement, HI, LO, MI, TWO_TO_LIMB};
use std::array;

/// All foreign field operations allowed
#[derive(PartialEq, Eq, Debug, Copy, Clone)]
pub enum FFOps {
    /// Addition
    Add,
    /// Subtraction
    Sub,
    /// TODO: Multiplication
    Mul,
}

// Given a left and right inputs to an addition or subtraction, and a modulus, it computes
// all necessary values needed for the witness layout. Meaning:
// - the result of the addition/subtraction as a ForeignElement
// - the sign of the operation
// - the overflow flag
// - the carry_lo and carry_mi values
fn compute_subadd_values<F: PrimeField>(
    left_input: &ForeignElement<F, 3>,
    right_input: &ForeignElement<F, 4>,
    opcode: FFOps,
    foreign_modulus: &ForeignElement<F, 3>,
) -> (ForeignElement<F, 3>, F, F, F, F) {
    assert_ne!(opcode, FFOps::Mul);

    let two_to_limb = F::from(TWO_TO_LIMB);

    // Compute bigint version of the inputs
    let left = left_input.to_big();
    let right = right_input.to_big();

    // Clarification:
    let right_hi = right_input[3] * two_to_limb + right_input[HI]; // This allows to store 2^88 in the high limb

    let modulus = foreign_modulus.to_big();

    // Addition or subtraction
    let sign = if opcode == FFOps::Add {
        F::one()
    } else {
        -F::one()
    };

    // Overflow if addition and greater than modulus or
    // underflow if subtraction and less than zero
    let has_overflow = if opcode == FFOps::Add {
        left.clone() + right.clone() >= modulus
    } else {
        left < right
    };

    // 0 for no overflow
    // -1 for underflow
    // +1 for overflow
    let field_overflow = if has_overflow { sign } else { F::zero() };

    // Compute the result
    // result = left + sign * right - field_overflow * modulus
    // TODO: unluckily, we cannot do it in one line if we keep these types, because one
    //       cannot combine field elements and biguints in the same operation automatically
    let result = ForeignElement::from_biguint({
        if opcode == FFOps::Add {
            if !has_overflow {
                // normal addition
                left + right
            } else {
                // overflow
                left + right - modulus
            }
        } else if opcode == FFOps::Sub {
            if !has_overflow {
                // normal subtraction
                left - right
            } else {
                // underflow
                modulus + left - right
            }
        } else {
            unreachable!()
        }
    });

    // c1 = r2 - a2 - b2 + q · f2
    // c0 = r1 - a1 - b1 + q · f1 + 2^88 · c1
    let carry_mi =
        result[HI] - left_input[HI] - sign * right_hi + field_overflow * foreign_modulus[HI];
    let carry_lo = result[MI] - left_input[MI] - sign * right_input[MI]
        + field_overflow * foreign_modulus[MI]
        + two_to_limb * carry_mi;
    (result, sign, field_overflow, carry_lo, carry_mi)
}

/// Creates a FFAdd witness (including range checks, `ForeignFieldAdd` rows, and one `ForeignFieldFin` row.)
/// inputs: list of all inputs to the chain of additions/subtractions
/// opcode: true for addition, false for subtraction
/// modulus: modulus of the foreign field
pub fn create_witness<F: PrimeField>(
    inputs: &Vec<BigUint>,
    opcodes: &Vec<FFOps>,
    modulus: BigUint,
) -> [Vec<F>; COLUMNS] {
    let num = inputs.len() - 1; // number of chained additions

    // make sure there are as many operands as operations
    assert_eq!(opcodes.len(), num);

    // Make sure that the inputs are smaller than the modulus just in case
    let inputs: Vec<BigUint> = inputs.iter().map(|input| input % modulus.clone()).collect();

    let mut witness = array::from_fn(|_| vec![F::zero(); 0]);

    let foreign_modulus = ForeignElement::from_biguint(modulus);

    // Create multi-range-check witness for first left input
    let mut left = ForeignElement::from_biguint(inputs[LO].clone());
    extend_witness(&mut witness, left.clone());
    let mut add_values: Vec<(F, F, F, F)> = vec![];
    for i in 0..num {
        let right = ForeignElement::from_biguint(inputs[i + 1].clone());
        let (output, sign, overflow, carry_lo, carry_mi) =
            compute_subadd_values(&left, &right, opcodes[i], &foreign_modulus);
        // Create multi-range-check witness for right_input (left_input was done in previous iteration) and output
        // We only obtain the 3 lower limbs of right because the range check takes only 264 bits now
        let right_3_limb = ForeignElement::new([right[LO], right[MI], right[HI]]);
        extend_witness(&mut witness, right_3_limb);
        extend_witness(&mut witness, output.clone());

        add_values.append(&mut vec![(sign, overflow, carry_lo, carry_mi)]);
        left = output; // output
    }

    // Compute values for final bound check, needs a 4 limb right input
    let right = ForeignElement::<F, 4>::from_biguint(BigUint::from(TWO_TO_LIMB).pow(3));

    let (bound, sign, overflow, bound_carry_lo, bound_carry_mi) =
        compute_subadd_values(&left, &right, FFOps::Add, &foreign_modulus);
    // Make sure they have the right value
    assert_eq!(sign, F::one());
    assert_eq!(overflow, F::one());

    // Final RangeCheck for bound
    extend_witness(&mut witness, bound);
    let mut offset = witness[LO].len(); // number of witness rows of the gadget before the first row of the addition gate

    // Include FFAdds gates for operations and final bound check

    for (i, value) in add_values.iter().enumerate() {
        // Create foreign field addition row
        for w in &mut witness {
            w.extend(std::iter::repeat(F::zero()).take(1));
        }

        let (sign, overflow, carry_lo, carry_mi) = *value;

        // ForeignFieldAdd row and Zero row
        init_foreign_field_add_rows(
            &mut witness,
            offset,
            i,
            sign,
            overflow,
            [carry_lo, carry_mi],
        );
        offset += 1;
    }

    for w in &mut witness {
        w.extend(std::iter::repeat(F::zero()).take(2));
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
//     * ValueLimb := contiguous range of bits extracted from a value
//
// TODO: Currently located in range check, but could be moved elsewhere
pub enum WitnessCell<F: Field> {
    Standard(range_check::witness::WitnessCell),
    FieldElement(FieldElementCell),
    Constant(F),
    Ignore,
}

/// Witness cell containing a type of value that is a field element
pub enum FieldElementType {
    Overflow,
    Carry,
    Sign,
}

pub struct FieldElementCell {
    pub kind: FieldElementType,
    pub limb_idx: usize,
}

impl FieldElementCell {
    pub const fn create<F: Field>(kind: FieldElementType, limb_idx: usize) -> WitnessCell<F> {
        WitnessCell::FieldElement(FieldElementCell { kind, limb_idx })
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
            FieldElementCell::create(FieldElementType::Sign, 0),         // sign
            FieldElementCell::create(FieldElementType::Overflow, 0),     // field_overflow
            FieldElementCell::create(FieldElementType::Carry, LO),       // carry_lo
            FieldElementCell::create(FieldElementType::Carry, MI),       // carry_mi
            WitnessCell::Standard(ZeroWitnessCell::create()),
            WitnessCell::Standard(ZeroWitnessCell::create()),
            WitnessCell::Standard(ZeroWitnessCell::create()),
            WitnessCell::Standard(ZeroWitnessCell::create()),
            WitnessCell::Standard(ZeroWitnessCell::create()),
        ],
    ];

    for (row, wit) in witness_shape.iter().enumerate() {
        for (col, cell) in wit.iter().enumerate() {
            handle_ffadd_rows(witness, cell, (row, col), offset, sign, overflow, carry);
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
    let witness_shape: [[WitnessCell<F>; COLUMNS]; 2] = [
        [
            // ForeignFieldFin row
            WitnessCell::Standard(CopyWitnessCell::create(out_row, 0)), // result_lo
            WitnessCell::Standard(CopyWitnessCell::create(out_row + 1, 0)), // result_mi
            WitnessCell::Standard(CopyWitnessCell::create(out_row + 2, 0)), // result_hi
            WitnessCell::Constant(F::zero()),                           // 0
            WitnessCell::Constant(F::zero()),                           // 0
            WitnessCell::Constant(F::from(TWO_TO_LIMB)),                // 2^88
            WitnessCell::Constant(F::one()),                            // sign
            WitnessCell::Constant(F::one()),                            // field_overflow
            FieldElementCell::create(FieldElementType::Carry, LO),      // carry_lo
            FieldElementCell::create(FieldElementType::Carry, MI),      // carry_mi
            WitnessCell::Standard(ZeroWitnessCell::create()),
            WitnessCell::Standard(ZeroWitnessCell::create()),
            WitnessCell::Standard(ZeroWitnessCell::create()),
            WitnessCell::Standard(ZeroWitnessCell::create()),
            WitnessCell::Standard(ZeroWitnessCell::create()),
        ],
        [
            // Zero Row
            WitnessCell::Standard(CopyWitnessCell::create(bound_row, 0)), // bound_lo
            WitnessCell::Standard(CopyWitnessCell::create(bound_row + 1, 0)), // bound_mi
            WitnessCell::Standard(CopyWitnessCell::create(bound_row + 2, 0)), // bound_hi
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

    for (row, wit) in witness_shape.iter().enumerate() {
        for (col, cell) in wit.iter().enumerate() {
            handle_ffadd_rows(
                witness,
                cell,
                (row, col),
                offset,
                F::zero(),
                F::zero(),
                carry,
            );
        }
    }
}

fn handle_ffadd_rows<F: PrimeField>(
    witness: &mut [Vec<F>; COLUMNS],
    witness_cell: &WitnessCell<F>,
    coordinates: (usize, usize), /* row, col */
    offset: usize,
    sign: F,
    overflow: F,
    carry: [F; 2],
) {
    let (row, col) = coordinates;
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
        WitnessCell::FieldElement(elem_cell) => {
            witness[col][offset + row] = {
                match elem_cell.kind {
                    FieldElementType::Overflow => overflow,
                    FieldElementType::Carry => carry[elem_cell.limb_idx],
                    FieldElementType::Sign => sign,
                }
            }
        }
        WitnessCell::Constant(field_elem) => witness[col][offset + row] = *field_elem,
        WitnessCell::Ignore => (),
    }
}
