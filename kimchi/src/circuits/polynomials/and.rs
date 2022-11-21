//! This module includes the AND gadget implementation and the witness creation code.
//! Note that this module does not need any new gate type for the AND operation.
use std::array;

use super::{
    generic::GenericGateSpec,
    xor::{init_xor, num_xors},
};
use crate::circuits::{
    gate::{CircuitGate, Connect},
    polynomial::COLUMNS,
    wires::Wire,
};
use ark_ff::PrimeField;
use num_bigint::BigUint;
use o1_utils::{big_bit_ops::big_and, big_xor, field_helpers::FieldFromBig, FieldHelpers};

impl<F: PrimeField> CircuitGate<F> {
    /// Creates an AND gadget for `bits` length.
    /// The full operation being performed is the following:
    /// `a AND b = 1/2 * (a + b - (a XOR b))`
    /// Includes:
    /// - num_xors Xor16 gates to perform `xor = a XOR b`
    /// - 1 Generic gate to constrain the final row to be zero with itself
    /// - 1 double Generic gate to perform the AND operation as `a + b = sum` and `2 * and = sum - xor`
    /// Outputs tuple (next_row, circuit_gates) where
    /// - next_row  : next row after this gate
    /// - gates     : vector of circuit gates comprising this gate
    pub fn create_and(new_row: usize, bits: usize) -> (usize, Vec<Self>) {
        let xor_row = new_row;
        let (and_row, mut gates) = Self::create_xor(xor_row, bits);
        let sum = GenericGateSpec::Add {
            left_coeff: Some(1u32.into()),
            right_coeff: Some(1u32.into()),
            output_coeff: Some(-F::one()),
        };
        let and = GenericGateSpec::Add {
            left_coeff: Some(F::one()),
            right_coeff: Some(-F::one()),
            output_coeff: Some(-F::from(2u32)),
        };
        gates.push(Self::create_generic_gadget(
            Wire::for_row(and_row),
            sum,
            Some(and),
        ));
        // connect the XOR output to the right input of the second generic gate
        gates.connect_cell_pair((xor_row, 2), (and_row, 4));
        // connect the sum output to the left input of the second generic gate
        gates.connect_cell_pair((and_row, 2), (and_row, 3));

        (gates.len(), gates)
    }
}

/// Create a And for less than 255 bits (native field) starting at row 0
/// Input: first input, second input, and desired byte length
/// Panics if the input is too large for the field
pub fn create_and_witness<F: PrimeField>(
    input1: &BigUint,
    input2: &BigUint,
    bytes: usize,
) -> [Vec<F>; COLUMNS] {
    if *input1 >= F::modulus_biguint() || *input2 >= F::modulus_biguint() {
        panic!("Input too large for the native field");
    }
    // Compute BigUint output of AND, XOR
    let and_output = big_and(input1, input2, bytes);
    let xor_output = big_xor(input1, input2);
    // Transform BigUint values to field elements
    let field_in1 = F::from_biguint(input1.clone()).unwrap();
    let field_in2 = F::from_biguint(input2.clone()).unwrap();
    let field_xor = F::from_biguint(xor_output).unwrap();
    let field_and = F::from_biguint(and_output).unwrap();
    let field_sum = field_in1 + field_in2;

    let and_row = num_xors(bytes * 8) + 1;
    let mut and_witness: [Vec<F>; COLUMNS] = array::from_fn(|_| vec![F::zero(); and_row + 1]);

    init_xor(
        &mut and_witness,
        0,
        bytes * 8,
        (field_in1, field_in2, field_xor),
    );
    // Fill in double generic witness
    and_witness[0][and_row] = field_in1;
    and_witness[1][and_row] = field_in2;
    and_witness[2][and_row] = field_sum;
    and_witness[3][and_row] = field_sum;
    and_witness[4][and_row] = field_xor;
    and_witness[5][and_row] = field_and;

    and_witness
}
