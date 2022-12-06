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
use ark_ff::{PrimeField, SquareRootField};
use num_bigint::BigUint;
use o1_utils::{big_bits, BitOps, FieldHelpers};

//~ We implement the AND gadget making use of the XOR gadget and the Generic gate. A new gate type is not needed, but we could potentially
//~ add one `And16` gate type reusing the same ideas of `Xor16` so as to save one final generic gate, at the cost of one additional AND
//~ lookup table that would have the same size as that of the Xor.
//~ For now, we are willing to pay this small overhead and produce AND gadget as follows:
//~
//~ We observe that we can express bitwise addition as follows:
//~ $$ A + B = (A \oplus B) + 2 \cdot (A \wedge B) $$
//~ where $\oplus$ is the bitwise XOR operation, $\wedge$ is the bitwise AND operation, and $+$ is the addition operation.
//~ In other words, the value of the addition is nothing but the XOR of its operands, plus the carry bit if both operands are 1.
//~ Thus, we can rewrite the above equation to obtain a definition of the AND operation as follows:
//~ $$ A \& B = \frac{A + B - (A \oplus B)}{2} $$
//~ Let us define the following operations for better readability:
//~ ```
//~ a + b = sum
//~ a ^ b = xor
//~ a & b = and
//~ ```
//~ Then, we can rewrite the above equation as follows:
//~ $$ 2 \cdot and = sum - xor $$
//~ which can be expressed as a double generic gate.
//~
//~ Then, our AND gadget for $n$ bytes looks as follows:
//~ * $n/8$ Xor16 gates
//~ * 1 (single) Generic gate to check the constant zero
//~ * 1 (double) Generic gate to check sum and the conjunction equations
//~
//~ Finally, we connect the wires in the following positions (apart from the ones already connected for the XOR gates):
//~ * Column 2 of the first Xor16 row (the output of the XOR operation) is connected to the right input of the second generic operation of the last row.
//~ * Column 2 of the first generic operation of the last row is connected to the left input of the second generic operation of the last row.
//~ Meaning,
//~ * the `xor` in `a ^ b = xor` is connected to the `xor` in `2 \cdot and = sum - xor`
//~ * the `sum` in `a + b = sum` is connected to the `sum` in `2 \cdot and = sum - xor`

impl<F: PrimeField + SquareRootField> CircuitGate<F> {
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
    pub fn create_and(new_row: usize, bytes: usize) -> (usize, Vec<Self>) {
        let xor_row = new_row;
        let (and_row, mut gates) = Self::create_xor_gadget(xor_row, bytes * 8);
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

/// Create a And for inputs as field elements starting at row 0
/// Input: first input, second input, and desired byte length
/// Panics if the input is too large for the chosen number of bytes
pub fn create_and_witness<F: PrimeField>(input1: F, input2: F, bytes: usize) -> [Vec<F>; COLUMNS] {
    let input1_big = input1.to_biguint();
    let input2_big = input2.to_biguint();
    if bytes * 8 < big_bits(&input1_big) || bytes * 8 < big_bits(&input2_big) {
        panic!("Bytes must be greater or equal than the inputs length");
    }

    // Compute BigUint output of AND, XOR
    let big_and = BigUint::bitand(&input1_big, &input2_big, bytes);
    let big_xor = BigUint::bitxor(&input1_big, &input2_big);
    // Transform BigUint values to field elements
    let xor = F::from_biguint(big_xor).unwrap();
    let and = F::from_biguint(big_and).unwrap();
    let sum = input1 + input2;

    let and_row = num_xors(bytes * 8) + 1;
    let mut and_witness: [Vec<F>; COLUMNS] = array::from_fn(|_| vec![F::zero(); and_row + 1]);

    init_xor(&mut and_witness, 0, bytes * 8, (input1, input2, xor));
    // Fill in double generic witness
    and_witness[0][and_row] = input1;
    and_witness[1][and_row] = input2;
    and_witness[2][and_row] = sum;
    and_witness[3][and_row] = sum;
    and_witness[4][and_row] = xor;
    and_witness[5][and_row] = and;

    and_witness
}
