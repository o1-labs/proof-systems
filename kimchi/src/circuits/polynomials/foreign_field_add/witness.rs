//! This module computes the witness of a foreign field addition circuit.

use crate::circuits::witness::Variables;
use crate::{
    circuits::{
        polynomial::COLUMNS,
        polynomials::range_check,
        witness::{self, ConstantCell, CopyCell, VariableCell, WitnessCell},
    },
    variable_map,
};
use ark_ff::PrimeField;
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

// A Foreign Field Addition Values
#[derive(PartialEq, Eq, Debug, Clone)]
struct FFAddValues<F: PrimeField> {
    left: ForeignElement<F, 3>,
    right: ForeignElement<F, 4>,
    output: ForeignElement<F, 3>,
    sign: F,
    ovf: F,
    carry: F,
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
) -> FFAddValues<F> {
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

    // c = [ (a1 * 2^88 + a0) + s * (b1 * 2^88 + b0) - q * (f1 * 2^88 + f0) - (r1 * 2^88 + r0) ] / 2^176
    //  <=>
    // c = r2 - a2 - s*b2 + q*f2

    let carry_bot: F = (bottom(&left_input[LO], &left_input[MI])
        + bottom(&right_input[LO], &right_input[MI]) * sign
        - bottom(&foreign_modulus[LO], &foreign_modulus[MI]) * field_overflow
        - bottom(&result[LO], &result[MI]))
        / (two_to_limb * two_to_limb);

    let carry_top: F =
        result[HI] - left_input[HI] - sign * right_hi + field_overflow * foreign_modulus[HI];

    // Check that both ways of computing the carry value are equal
    assert_eq!(carry_top, carry_bot);

    FFAddValues {
        left: left_input.clone(),
        right: right_input.clone(),
        output: result,
        sign,
        ovf: field_overflow,
        carry: carry_bot,
    }
}

// Returns the bottom composition of an element from its low and middle limbs
fn bottom<F: PrimeField>(lo: &F, mi: &F) -> F {
    lo.clone() + mi.clone() * F::from(TWO_TO_LIMB)
}

/// Creates a FFAdd witness (including optional multi range checks, `ForeignFieldAdd` rows, and one `ForeignFieldFin` row.) starting in zero row
/// inputs: list of all inputs to the chain of additions/subtractions
/// opcode: true for addition, false for subtraction
/// modulus: modulus of the foreign field
pub fn create_ffadd_chain_witness<F: PrimeField>(
    inputs: &Vec<BigUint>,
    opcodes: &Vec<FFOps>,
    modulus: BigUint,
    range_checks: bool,
) -> [Vec<F>; COLUMNS] {
    let num = inputs.len() - 1; // number of chained additions

    // make sure there are as many operands as operations
    assert_eq!(opcodes.len(), num);

    // Make sure that the inputs are smaller than the modulus just in case
    let inputs: Vec<BigUint> = inputs.iter().map(|input| input % modulus.clone()).collect();

    let mut witness = array::from_fn(|_| vec![F::zero(); 0]);

    let foreign_modulus = ForeignElement::from_biguint(modulus);

    let mut left = ForeignElement::from_biguint(inputs[LO].clone());
    // Create multi-range-check witness for first left input
    if range_checks {
        range_check::witness::extend(&mut witness, left.clone());
    }
    let mut values: Vec<FFAddValues<F>> = vec![];
    for i in 0..num {
        let right = ForeignElement::from_biguint(inputs[i + 1].clone());
        let add_values = compute_ffadd_values(&left, &right, opcodes[i], &foreign_modulus);
        // We only obtain the 3 lower limbs of right because the range check takes only 264 bits now
        let right_3_limb = ForeignElement::new([right[LO], right[MI], right[HI]]);
        // Create multi-range-check witness for right_input (left_input was done in previous iteration) and output
        if range_checks {
            range_check::witness::extend(&mut witness, right_3_limb);
            range_check::witness::extend(&mut witness, add_values.output.clone());
        }

        values.push(add_values.clone());
        left = add_values.output.clone(); // output
    }

    // Compute values for final bound check, needs a 4 limb right input
    let right = ForeignElement::<F, 4>::from_biguint(BigUint::from(TWO_TO_LIMB).pow(3));

    let bound_values = compute_ffadd_values(&left, &right, FFOps::Add, &foreign_modulus);
    // Make sure they have the right value
    assert_eq!(bound_values.sign, F::one());
    assert_eq!(bound_values.ovf, F::one());

    // Final RangeCheck for bound
    if range_checks {
        range_check::witness::extend(&mut witness, bound_values.output.clone());
    }
    let mut offset = if range_checks {
        witness[LO].len() // number of witness rows of the gadget before the first row of the addition gate
    } else {
        0
    };

    // Include FFAdds gates for operations and final bound check

    for (i, value) in values.iter().enumerate() {
        // Create foreign field addition row
        for w in &mut witness {
            w.extend(std::iter::repeat(F::zero()).take(1));
        }

        // ForeignFieldAdd row and Zero row
        if range_checks {
            init_ff_add_rows_rc(&mut witness, offset, i, value.sign, value.ovf, value.carry);
        } else {
            let right = ForeignElement::new([value.right[LO], value.right[MI], value.right[HI]]);
            init_ff_add_rows(
                &mut witness,
                offset,
                value.left.clone(),
                right,
                value.sign,
                value.ovf,
                value.carry,
            )
        }
        offset += 1;
    }

    for w in &mut witness {
        w.extend(std::iter::repeat(F::zero()).take(2));
    }
    if range_checks {
        init_ff_fin_rows_rc(&mut witness, offset, num, bound_values.carry);
    } else {
        init_ff_fin_rows(
            &mut witness,
            offset,
            bound_values.left,
            bound_values.output.clone(),
            bound_values.carry,
        );
    }

    witness
}

fn init_ff_add_rows<F: PrimeField>(
    witness: &mut [Vec<F>; COLUMNS],
    offset: usize,
    left: ForeignElement<F, 3>,
    right: ForeignElement<F, 3>,
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

fn init_ff_add_rows_rc<F: PrimeField>(
    witness: &mut [Vec<F>; COLUMNS],
    offset: usize,
    index: usize,
    sign: F,
    overflow: F,
    carry: F,
) {
    let left_row = 8 * index;
    let right_row = 8 * index + 4;
    let witness_shape: Vec<[Box<dyn WitnessCell<F>>; COLUMNS]> = vec![
        // ForeignFieldAdd row
        [
            CopyCell::create(left_row, 0),      // left_input_lo
            CopyCell::create(left_row + 1, 0),  // left_input_mi
            CopyCell::create(left_row + 2, 0),  // left_input_hi
            CopyCell::create(right_row, 0),     // right_input_lo
            CopyCell::create(right_row + 1, 0), // right_input_mi
            CopyCell::create(right_row + 2, 0), // right_input_hi
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
        &variable_map!["sign" => sign, "overflow" => overflow, "carry" => carry],
    );
}

fn init_ff_fin_rows_rc<F: PrimeField>(
    witness: &mut [Vec<F>; COLUMNS],
    offset: usize,
    num: usize,
    carry: F,
) {
    let out_row = 8 * num; // row where the final result is stored in RC
    let bound_row = 8 * num + 4; // row where the final bound is stored in RC
    let witness_shape: Vec<[Box<dyn WitnessCell<F>>; COLUMNS]> = vec![
        [
            // ForeignFieldFin row
            CopyCell::create(out_row, 0),               // result_lo
            CopyCell::create(out_row + 1, 0),           // result_mi
            CopyCell::create(out_row + 2, 0),           // result_hi
            ConstantCell::create(F::zero()),            // 0
            ConstantCell::create(F::zero()),            // 0
            ConstantCell::create(F::from(TWO_TO_LIMB)), // 2^88
            ConstantCell::create(F::one()),             // sign
            ConstantCell::create(F::one()),             // field_overflow
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
            CopyCell::create(bound_row, 0),     // bound_lo
            CopyCell::create(bound_row + 1, 0), // bound_mi
            CopyCell::create(bound_row + 2, 0), // bound_hi
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
        &variable_map!["carry" => carry],
    );
}

fn init_ff_fin_rows<F: PrimeField>(
    witness: &mut [Vec<F>; COLUMNS],
    offset: usize,
    result: ForeignElement<F, 3>,
    bound: ForeignElement<F, 3>,
    carry: F,
) {
    let witness_shape: Vec<[Box<dyn WitnessCell<F>>; COLUMNS]> = vec![
        [
            // ForeignFieldFin row
            VariableCell::create("result_lo"),
            VariableCell::create("result_mi"),
            VariableCell::create("result_hi"),
            ConstantCell::create(F::zero()),            // 0
            ConstantCell::create(F::zero()),            // 0
            ConstantCell::create(F::from(TWO_TO_LIMB)), // 2^88
            ConstantCell::create(F::one()),             // sign
            ConstantCell::create(F::one()),             // field_overflow
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
        &variable_map!["carry" => carry, "result_lo" => result[LO], "result_mi" => result[MI], "result_hi" => result[HI], "bound_lo" => bound[LO], "bound_mi" => bound[MI], "bound_hi" => bound[HI]],
    );
}
