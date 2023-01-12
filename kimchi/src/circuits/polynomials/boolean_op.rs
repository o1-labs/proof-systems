//! Generic boolean operation gate
//!
//! This gate constrains at most 2 boolean operations per row, each of the form
//!
//! ```text
//! coeff0 * (left_input AND right_input) + coeff1 * (left_input OR right_input) = output
//! ```
//!
//! where coeff0 and coeff1 are the first two gate coefficients.
//!
//! Layout
//!
//! | col | `BooleanOp`             |
//! | --- | --------------------- |
//! |   0 | `left_input0`  (copy) |
//! |   1 | `right_input0` (copy) |
//! |   2 | `output0`      (copy) |
//! |   3 | `left_input1`  (copy) |
//! |   4 | `right_input1` (copy) |
//! |   5 | `output1`      (copy) |
//! |   6 |                       |
//! |   7 |                       |
//! |   8 |                       |
//! |   9 |                       |
//! |  10 |                       |
//! |  11 |                       |
//! |  12 |                       |
//! |  13 |                       |
//! |  14 |                       |
//!
//! The following table explains how to setup the coefficients to get different boolean operations.
//!
//! | Operation | coeff0 | coeff1 |
//! | --------- | ------ | ------ |
//! | `AND`     | `1`    | `0`    |
//! | `OR`      | `-1`   | `1`    |
//! | `XOR`     | `-2`   | `1`    |
//!
//! The setup is identical for the second boolean operation using coeff2 and coeff3.
//!
//! Constraints
//!
//!   1) (left_input0 - 1) * left_input0
//!   2) (left_input1 - 1) * left_input1
//!   3) (right_input0 - 1) * right_input0
//!   4) (right_input1 - 1) * right_input1
//!   5) coeff0 * (left_input0 AND right_input0) + coeff1 * (left_input0 OR right_input0) = output0
//!   6) coeff2 * (left_input1 AND right_input1) + coeff3 * (left_input1 OR right_input1) = output1
//!

use std::{array, marker::PhantomData};

use ark_ff::{PrimeField, SquareRootField};

use crate::{
    circuits::{
        argument::{Argument, ArgumentEnv, ArgumentType},
        expr::constraints::ExprOps,
        gate::{CircuitGate, GateType},
        polynomial::COLUMNS,
        wires::Wire,
        witness::{self, ConstantCell, VariableCell, Variables, WitnessCell},
    },
    variable_map,
};

fn boolean_operation<F: PrimeField, T: ExprOps<F>>(
    left_input: T,
    right_input: T,
    coeff0: T,
    coeff1: T,
) -> T {
    coeff0 * (left_input.clone() * right_input.clone()) + coeff1 * (left_input + right_input)
}

/// Generic boolean operation gate
///    * This gate operates on the Curr row only
///    * Can constrain up to two boolean operations
#[derive(Default)]
pub struct BooleanOp<F>(PhantomData<F>);

impl<F> Argument<F> for BooleanOp<F>
where
    F: PrimeField,
{
    const ARGUMENT_TYPE: ArgumentType = ArgumentType::Gate(GateType::BooleanOp);
    const CONSTRAINTS: u32 = 6;
    // DEGREE is 3

    fn constraint_checks<T: ExprOps<F>>(env: &ArgumentEnv<F, T>) -> Vec<T> {
        let mut constraints = vec![];

        // Left operands
        let left_inputs = [env.witness_curr(0), env.witness_curr(3)];

        // Right operands
        let right_inputs = [env.witness_curr(1), env.witness_curr(4)];

        // Outputs
        let outputs = [env.witness_curr(2), env.witness_curr(5)];

        // C1-C2: left_inputs are boolean
        for left_input in left_inputs.clone() {
            constraints.push(left_input.boolean());
        }

        // C3-C4: right_inputs are boolean
        for right_input in right_inputs.clone() {
            constraints.push(right_input.boolean());
        }

        // C5-C6: c[i] * (left_input[i] AND right_input[i]) + c[i + 1] * (left_input[i] OR right_input[i]) = output[i]
        for i in 0..2 {
            constraints.push(
                boolean_operation(
                    left_inputs[i].clone(),
                    right_inputs[i].clone(),
                    env.coeff(i * 2),
                    env.coeff(i * 2 + 1),
                ) - outputs[i].clone(),
            );
        }

        constraints
    }
}

impl<F: PrimeField + SquareRootField> CircuitGate<F> {
    /// Create generic boolean operation gate
    ///     Inputs the starting row and gate coefficients
    ///     Outputs tuple (next_row, circuit_gates) where
    ///       next_row      - next row after this gate
    ///       circuit_gates - vector of circuit gates comprising this gate
    pub fn create_boolean_op(start_row: usize, coeffs: &[F; 4]) -> (usize, Vec<Self>) {
        let circuit_gates = vec![CircuitGate {
            typ: GateType::BooleanOp,
            wires: Wire::for_row(start_row),
            coeffs: coeffs.to_vec(),
        }];

        (start_row + circuit_gates.len(), circuit_gates)
    }

    /// Create generic boolean gate by extending the existing gates
    pub fn extend_boolean_op(gates: &mut Vec<Self>, curr_row: &mut usize, coeffs: &[F; 4]) {
        let (next_row, circuit_gates) = Self::create_boolean_op(*curr_row, coeffs);
        *curr_row = next_row;
        gates.extend_from_slice(&circuit_gates);
    }

    /// Create a boolean AND gate
    ///     Inputs the starting row
    ///     Outputs tuple (next_row, circuit_gates) where
    ///       next_row      - next row after this gate
    ///       circuit_gates - vector of circuit gates comprising this gate
    pub fn create_boolean_and(start_row: usize) -> (usize, Vec<Self>) {
        let circuit_gates = vec![CircuitGate {
            typ: GateType::BooleanOp,
            wires: Wire::for_row(start_row),
            coeffs: vec![F::one(), F::zero(), F::one(), F::zero()],
        }];

        (start_row + circuit_gates.len(), circuit_gates)
    }

    /// Create boolean AND gate by extending the existing gates
    pub fn extend_boolean_and(gates: &mut Vec<Self>, curr_row: &mut usize) {
        let (next_row, circuit_gates) = Self::create_boolean_and(*curr_row);
        *curr_row = next_row;
        gates.extend_from_slice(&circuit_gates);
    }

    /// Create a boolean OR gate
    ///     Inputs the starting row
    ///     Outputs tuple (next_row, circuit_gates) where
    ///       next_row      - next row after this gate
    ///       circuit_gates - vector of circuit gates comprising this gate
    pub fn create_boolean_or(start_row: usize) -> (usize, Vec<Self>) {
        let circuit_gates = vec![CircuitGate {
            typ: GateType::BooleanOp,
            wires: Wire::for_row(start_row),
            coeffs: vec![-F::one(), F::one(), -F::one(), F::one()],
        }];

        (start_row + circuit_gates.len(), circuit_gates)
    }

    /// Create boolean OR gate by extending the existing gates
    pub fn extend_boolean_or(gates: &mut Vec<Self>, curr_row: &mut usize) {
        let (next_row, circuit_gates) = Self::create_boolean_or(*curr_row);
        *curr_row = next_row;
        gates.extend_from_slice(&circuit_gates);
    }

    /// Create a boolean XOR gate
    ///     Inputs the starting row
    ///     Outputs tuple (next_row, circuit_gates) where
    ///       next_row      - next row after this gate
    ///       circuit_gates - vector of circuit gates comprising this gate
    pub fn create_boolean_xor(start_row: usize) -> (usize, Vec<Self>) {
        let circuit_gates = vec![CircuitGate {
            typ: GateType::BooleanOp,
            wires: Wire::for_row(start_row),
            coeffs: vec![-F::from(2u64), F::one(), -F::from(2u64), F::one()],
        }];

        (start_row + circuit_gates.len(), circuit_gates)
    }

    /// Create boolean XOR gate by extending the existing gates
    pub fn extend_boolean_xor(gates: &mut Vec<Self>, curr_row: &mut usize) {
        let (next_row, circuit_gates) = Self::create_boolean_xor(*curr_row);
        *curr_row = next_row;
        gates.extend_from_slice(&circuit_gates);
    }
}

fn layout<F: PrimeField>() -> [[Box<dyn WitnessCell<F>>; COLUMNS]; 1] {
    [
        [
            VariableCell::create("left_input0"),
            VariableCell::create("right_input0"),
            VariableCell::create("output0"),
            VariableCell::create("left_input1"),
            VariableCell::create("right_input1"),
            VariableCell::create("output1"),
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
    ]
}

/// Create witness for generic boolean gate
pub fn create<F: PrimeField>(
    left_input0: &F,
    right_input0: &F,
    left_input1: &F,
    right_input1: &F,
    coeffs: &[F; 4],
) -> [Vec<F>; COLUMNS] {
    // Compute outputs for witness (reuse constraints function)
    let output0 = boolean_operation(*left_input0, *right_input0, coeffs[0], coeffs[1]);
    let output1 = boolean_operation(*left_input1, *right_input1, coeffs[2], coeffs[3]);

    // Generate witness
    let mut witness: [Vec<F>; COLUMNS] = array::from_fn(|_| vec![F::zero(); 1]);
    witness::init(
        &mut witness,
        0,
        &layout(),
        &variable_map!("left_input0" => *left_input0,
                                 "right_input0" => *right_input0,
                                 "output0" => output0,
                                 "left_input1" => *left_input1,
                                 "right_input1" => *right_input1,
                                 "output1" => output1),
    );

    witness
}

/// Extend an existing witness with a generic boolean gate
pub fn extend<F: PrimeField>(
    witness: &mut [Vec<F>; COLUMNS],
    left_input0: &F,
    right_input0: &F,
    left_input1: &F,
    right_input1: &F,
    coeffs: &[F; 4],
) {
    let boolean_op_witness = create(left_input0, right_input0, left_input1, right_input1, coeffs);
    for col in 0..COLUMNS {
        witness[col].extend(boolean_op_witness[col].iter())
    }
}

/// Create witness for boolean AND gate
pub fn create_and<F: PrimeField>(
    left_input0: &F,
    right_input0: &F,
    left_input1: &F,
    right_input1: &F,
) -> [Vec<F>; COLUMNS] {
    // Compute outputs for witness (reuse constraints function)
    let output0 = boolean_operation(*left_input0, *right_input0, F::one(), F::zero());
    let output1 = boolean_operation(*left_input1, *right_input1, F::one(), F::zero());

    // Generate witness
    let mut witness: [Vec<F>; COLUMNS] = array::from_fn(|_| vec![F::zero(); 1]);
    witness::init(
        &mut witness,
        0,
        &layout(),
        &variable_map!("left_input0" => *left_input0,
                                 "right_input0" => *right_input0,
                                 "output0" => output0,
                                 "left_input1" => *left_input1,
                                 "right_input1" => *right_input1,
                                 "output1" => output1),
    );

    witness
}

/// Extend an existing witness with a boolean AND gate
pub fn extend_and<F: PrimeField>(
    witness: &mut [Vec<F>; COLUMNS],
    left_input0: &F,
    right_input0: &F,
    left_input1: &F,
    right_input1: &F,
) {
    let boolean_and_witness = create_and(left_input0, right_input0, left_input1, right_input1);
    for col in 0..COLUMNS {
        witness[col].extend(boolean_and_witness[col].iter())
    }
}

/// Create witness for boolean OR gate
pub fn create_or<F: PrimeField>(
    left_input0: &F,
    right_input0: &F,
    left_input1: &F,
    right_input1: &F,
) -> [Vec<F>; COLUMNS] {
    // Compute outputs for witness (reuse constraints function)
    let output0 = boolean_operation(*left_input0, *right_input0, -F::one(), F::one());
    let output1 = boolean_operation(*left_input1, *right_input1, -F::one(), F::one());

    // Generate witness
    let mut witness: [Vec<F>; COLUMNS] = array::from_fn(|_| vec![F::zero(); 1]);
    witness::init(
        &mut witness,
        0,
        &layout(),
        &variable_map!("left_input0" => *left_input0,
                                 "right_input0" => *right_input0,
                                 "output0" => output0,
                                 "left_input1" => *left_input1,
                                 "right_input1" => *right_input1,
                                 "output1" => output1),
    );

    witness
}

/// Extend an existing witness with a boolean OR gate
pub fn extend_or<F: PrimeField>(
    witness: &mut [Vec<F>; COLUMNS],
    left_input0: &F,
    right_input0: &F,
    left_input1: &F,
    right_input1: &F,
) {
    let boolean_or_witness = create_or(left_input0, right_input0, left_input1, right_input1);
    for col in 0..COLUMNS {
        witness[col].extend(boolean_or_witness[col].iter())
    }
}

/// Create witness for boolean XOR gate
pub fn create_xor<F: PrimeField>(
    left_input0: &F,
    right_input0: &F,
    left_input1: &F,
    right_input1: &F,
) -> [Vec<F>; COLUMNS] {
    // Compute outputs for witness (reuse constraints function)
    let output0 = boolean_operation(*left_input0, *right_input0, -F::from(2u64), F::one());
    let output1 = boolean_operation(*left_input1, *right_input1, -F::from(2u64), F::one());

    // Generate witness
    let mut witness: [Vec<F>; COLUMNS] = array::from_fn(|_| vec![F::zero(); 1]);
    witness::init(
        &mut witness,
        0,
        &layout(),
        &variable_map!("left_input0" => *left_input0,
                                 "right_input0" => *right_input0,
                                 "output0" => output0,
                                 "left_input1" => *left_input1,
                                 "right_input1" => *right_input1,
                                 "output1" => output1),
    );

    witness
}

/// Extend an existing witness with a boolean XOR gate
pub fn extend_xor<F: PrimeField>(
    witness: &mut [Vec<F>; COLUMNS],
    left_input0: &F,
    right_input0: &F,
    left_input1: &F,
    right_input1: &F,
) {
    let boolean_xor_witness = create_xor(left_input0, right_input0, left_input1, right_input1);
    for col in 0..COLUMNS {
        witness[col].extend(boolean_xor_witness[col].iter())
    }
}
