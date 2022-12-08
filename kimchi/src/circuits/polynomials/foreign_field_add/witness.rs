//! This module computes the witness of a foreign field addition circuit.

use crate::circuits::expr::constraints::compact_limb;
use crate::circuits::witness::Variables;
use crate::{
    circuits::{
        polynomial::COLUMNS,
        witness::{self, ConstantCell, VariableCell, WitnessCell},
    },
    variable_map,
};
use ark_ff::PrimeField;
use num_bigint::BigUint;
use o1_utils::foreign_field::{
    BigUintForeignFieldHelpers, ForeignElement, ForeignFieldHelpers, HI, LO, MI,
};
use std::array;

/// All foreign field operations allowed
#[derive(PartialEq, Eq, Debug, Copy, Clone)]
pub enum FFOps {
    /// Addition
    Add,
    /// Subtraction
    Sub,
    /// Multiplication
    Mul,
}

// Given a left and right inputs to an addition or subtraction, and a modulus, it computes
// all necessary values needed for the witness layout. Meaning, it returns an [FFAddValues] instance
// - the result of the addition/subtraction as a ForeignElement
// - the sign of the operation
// - the overflow flag
// - the carry value
fn compute_ffadd_values<F: PrimeField>(
    left_input: &ForeignElement<F, 3>,
    right_input: &ForeignElement<F, 4>,
    opcode: FFOps,
    foreign_modulus: &ForeignElement<F, 3>,
) -> (ForeignElement<F, 3>, F, F, F) {
    assert_ne!(opcode, FFOps::Mul);

    // Compute bigint version of the inputs
    let left = left_input.to_biguint();
    let right = right_input.to_biguint();

    // Clarification:
    let right_hi = right_input[3] * F::two_to_limb() + right_input[HI]; // This allows to store 2^88 in the high limb

    let modulus = foreign_modulus.to_biguint();

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

    // c = [ (a1 * 2^88 + a0) + s * (b1 * 2^88 + b0) - q * (f1 * 2^88 + f0) - (r1 * 2^88 + r0) ] / 2^176
    //  <=>
    // c = r2 - a2 - s*b2 + q*f2

    let carry_bot: F = (compact_limb(&left_input[LO], &left_input[MI])
        + compact_limb(&right_input[LO], &right_input[MI]) * sign
        - compact_limb(&foreign_modulus[LO], &foreign_modulus[MI]) * field_overflow
        - compact_limb(&result[LO], &result[MI]))
        / F::two_to_2limb();

    let carry_top: F =
        result[HI] - left_input[HI] - sign * right_hi + field_overflow * foreign_modulus[HI];

    // Check that both ways of computing the carry value are equal
    assert_eq!(carry_top, carry_bot);

    (result, sign, field_overflow, carry_bot)
}

/// Creates a FFAdd witness (including `ForeignFieldAdd` rows, and one final `ForeignFieldAdd` row for bound) starting in zero row
/// inputs: list of all inputs to the chain of additions/subtractions
/// opcode: true for addition, false for subtraction
/// modulus: modulus of the foreign field
pub fn create<F: PrimeField>(
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

    let mut left = ForeignElement::from_biguint(inputs[0].clone());

    for i in 0..num {
        // Create foreign field addition row
        for w in &mut witness {
            w.extend(std::iter::repeat(F::zero()).take(1));
        }
        let right = ForeignElement::from_biguint(inputs[i + 1].clone());
        let (output, sign, ovf, carry) =
            compute_ffadd_values(&left, &right, opcodes[i], &foreign_modulus);
        init_ffadd_row(
            &mut witness,
            i,
            left.limbs,
            [right[LO], right[MI], right[HI]],
            sign,
            ovf,
            carry,
        );
        left = output; // output is next left input
    }

    extend_witness_bound_addition(&mut witness, &left.limbs, &foreign_modulus.limbs);

    witness
}

fn init_ffadd_row<F: PrimeField>(
    witness: &mut [Vec<F>; COLUMNS],
    offset: usize,
    left: [F; 3],
    right: [F; 3],
    sign: F,
    overflow: F,
    carry: F,
) {
    let witness_shape: Vec<[Box<dyn WitnessCell<F>>; COLUMNS]> = vec![
        // ForeignFieldAdd row
        [
            VariableCell::create("left_lo"),
            VariableCell::create("left_mi"),
            VariableCell::create("left_hi"),
            VariableCell::create("right_lo"),
            VariableCell::create("right_mi"),
            VariableCell::create("right_hi"),
            VariableCell::create("sign"),
            VariableCell::create("overflow"), // field_overflow
            VariableCell::create("carry"),    // carry bit
            ConstantCell::create(F::zero()),
            ConstantCell::create(F::zero()),
            ConstantCell::create(F::zero()),
            ConstantCell::create(F::zero()),
            ConstantCell::create(F::zero()),
            ConstantCell::create(F::zero()),
        ],
    ];

    witness::init(
        witness,
        offset,
        &witness_shape,
        &variable_map!["left_lo" => left[LO], "left_mi" => left[MI], "left_hi" => left[HI], "right_lo" => right[LO], "right_mi" => right[MI], "right_hi" => right[HI], "sign" => sign, "overflow" => overflow, "carry" => carry],
    );
}

fn init_bound_rows<F: PrimeField>(
    witness: &mut [Vec<F>; COLUMNS],
    offset: usize,
    result: &[F; 3],
    bound: &[F; 3],
    carry: &F,
) {
    let witness_shape: Vec<[Box<dyn WitnessCell<F>>; COLUMNS]> = vec![
        [
            // ForeignFieldAdd row
            VariableCell::create("result_lo"),
            VariableCell::create("result_mi"),
            VariableCell::create("result_hi"),
            ConstantCell::create(F::zero()),        // 0
            ConstantCell::create(F::zero()),        // 0
            ConstantCell::create(F::two_to_limb()), // 2^88
            ConstantCell::create(F::one()),         // sign
            ConstantCell::create(F::one()),         // field_overflow
            VariableCell::create("carry"),
            ConstantCell::create(F::zero()),
            ConstantCell::create(F::zero()),
            ConstantCell::create(F::zero()),
            ConstantCell::create(F::zero()),
            ConstantCell::create(F::zero()),
            ConstantCell::create(F::zero()),
        ],
        [
            // Zero Row
            VariableCell::create("bound_lo"),
            VariableCell::create("bound_mi"),
            VariableCell::create("bound_hi"),
            ConstantCell::create(F::zero()),
            ConstantCell::create(F::zero()),
            ConstantCell::create(F::zero()),
            ConstantCell::create(F::zero()),
            ConstantCell::create(F::zero()),
            ConstantCell::create(F::zero()),
            ConstantCell::create(F::zero()),
            ConstantCell::create(F::zero()),
            ConstantCell::create(F::zero()),
            ConstantCell::create(F::zero()),
            ConstantCell::create(F::zero()),
            ConstantCell::create(F::zero()),
        ],
    ];

    witness::init(
        witness,
        offset,
        &witness_shape,
        &variable_map!["carry" => *carry, "result_lo" => result[LO], "result_mi" => result[MI], "result_hi" => result[HI], "bound_lo" => bound[LO], "bound_mi" => bound[MI], "bound_hi" => bound[HI]],
    );
}

/// Create witness for bound computation addition gate
pub fn extend_witness_bound_addition<F: PrimeField>(
    witness: &mut [Vec<F>; COLUMNS],
    limbs: &[F; 3],
    foreign_field_modulus: &[F; 3],
) {
    // Convert to types used by this module
    let fe = ForeignElement::<F, 3>::new(*limbs);
    let foreign_field_modulus = ForeignElement::<F, 3>::new(*foreign_field_modulus);

    // Compute values for final bound check, needs a 4 limb right input
    let right_input = ForeignElement::<F, 4>::from_biguint(BigUint::binary_modulus());

    // Compute the bound and related witness data
    let (bound_output, bound_sign, bound_ovf, bound_carry) =
        compute_ffadd_values(&fe, &right_input, FFOps::Add, &foreign_field_modulus);
    // Make sure they have the right value
    assert_eq!(bound_sign, F::one());
    assert_eq!(bound_ovf, F::one());

    // Extend the witness for the add gate
    let offset = witness[0].len();
    for col in witness.iter_mut().take(COLUMNS) {
        col.extend(std::iter::repeat(F::zero()).take(2))
    }

    init_bound_rows(
        witness,
        offset,
        &fe.limbs,
        &bound_output.limbs,
        &bound_carry,
    );
}
