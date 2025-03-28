//! This module includes the AND gadget implementation and the witness creation code.
//! Note that this module does not need any new gate type for the AND operation.
use core::array;

use super::{
    generic::GenericGateSpec,
    xor::{init_xor, num_xors},
};
use crate::circuits::{
    gate::{CircuitGate, Connect},
    lookup::{
        self,
        tables::{GateLookupTable, LookupTable},
    },
    polynomial::COLUMNS,
    wires::Wire,
};
use ark_ff::PrimeField;
use num_bigint::BigUint;
use o1_utils::{BigUintFieldHelpers, BigUintHelpers, BitwiseOps, FieldHelpers, Two};

//~ We implement the AND gadget making use of the XOR gadget and the Generic gate. A new gate type is not needed, but we could potentially
//~ add an `And16` gate type reusing the same ideas of `Xor16` so as to save one final generic gate, at the cost of one additional AND
//~ lookup table that would have the same size as that of the Xor.
//~ For now, we are willing to pay this small overhead and produce AND gadget as follows:
//~
//~ We observe that we can express bitwise addition as follows:
//~ $$A + B = (A \oplus B) + 2 \cdot (A \wedge B)$$
//~
//~ where $\oplus$ is the bitwise XOR operation, $\wedge$ is the bitwise AND operation, and $+$ is the addition operation.
//~ In other words, the value of the addition is nothing but the XOR of its operands, plus the carry bit if both operands are 1.
//~ Thus, we can rewrite the above equation to obtain a definition of the AND operation as follows:
//~ $$A \wedge B = \frac{A + B - (A \oplus B)}{2}$$
//~ Let us define the following operations for better readability:
//~
//~ ```text
//~ a + b = sum
//~ a x b = xor
//~ a ^ b = and
//~ ```
//~
//~ Then, we can rewrite the above equation as follows:
//~ $$ 2 \cdot and = sum - xor $$
//~ which can be expressed as a double generic gate.
//~
//~ Then, our AND gadget for $n$ bytes looks as follows:
//~
//~ * $n/8$ Xor16 gates
//~ * 1 (single) Generic gate to check that the final row of the XOR chain is all zeros.
//~ * 1 (double) Generic gate to check sum $a + b = sum$ and the conjunction equation $2\cdot and = sum - xor$.
//~
//~ Finally, we connect the wires in the following positions (apart from the ones already connected for the XOR gates):
//~
//~ * Column 2 of the first Xor16 row (the output of the XOR operation) is connected to the right input of the second generic operation of the last row.
//~ * Column 2 of the first generic operation of the last row is connected to the left input of the second generic operation of the last row.
//~ Meaning,
//~
//~ * the `xor` in `a x b = xor` is connected to the `xor` in `2 \cdot and = sum - xor`
//~ * the `sum` in `a + b = sum` is connected to the `sum` in `2 \cdot and = sum - xor`

impl<F: PrimeField> CircuitGate<F> {
    /// Extends an AND gadget for `bytes` length.
    /// The full operation being performed is the following:
    /// `a AND b = 1/2 * (a + b - (a XOR b))`
    /// Includes:
    /// - num_xors Xor16 gates to perform `xor = a XOR b`
    /// - 1 Generic gate to constrain the final row to be zero with itself
    /// - 1 double Generic gate to perform the AND operation as `a + b = sum` and `2 * and = sum - xor`
    ///
    /// Input:
    /// - gates    : vector of circuit gates comprising the full circuit
    /// - bytes    : number of bytes of the AND operation
    ///
    /// Output:
    /// - next_row  : next row after this gate
    ///
    /// Warning:
    /// - if there's any public input for the and, don't forget to wire it
    pub fn extend_and(gates: &mut Vec<Self>, bytes: usize) -> usize {
        assert!(bytes > 0, "Bytes must be a positive number");
        let xor_row = gates.len();
        let and_row = Self::extend_xor_gadget(gates, bytes * 8);
        let (_, mut and_gates) = Self::create_and(and_row, bytes);
        // extend the whole circuit with the AND gadget
        gates.append(&mut and_gates);

        // connect the XOR inputs to the inputs of the first generic gate
        gates.connect_cell_pair((xor_row, 0), (and_row, 0));
        gates.connect_cell_pair((xor_row, 1), (and_row, 1));
        // connect the sum output of the first generic gate to the left input of the second generic gate
        gates.connect_cell_pair((and_row, 2), (and_row, 3));
        // connect the XOR output to the right input of the second generic gate
        gates.connect_cell_pair((xor_row, 2), (and_row, 4));

        gates.len()
    }

    // Creates an AND gadget for `bytes` length.
    // The full operation being performed is the following:
    // `a AND b = 1/2 * (a + b - (a XOR b))`
    // Includes:
    // - 1 double Generic gate to perform the AND operation as `a + b = sum` and `2 * and = sum - xor`
    // Input:
    // - new_row  : row where the AND generic gate starts
    // - bytes    : number of bytes of the AND operation
    // Outputs tuple (next_row, circuit_gates) where
    // - next_row  : next row after this gate
    // - gates     : vector of circuit gates comprising the AND double generic gate
    // Warning:
    // - don't forget to connect the wiring from the and
    fn create_and(new_row: usize, bytes: usize) -> (usize, Vec<Self>) {
        assert!(bytes > 0, "Bytes must be a positive number");

        // a + b = sum
        let sum = GenericGateSpec::Add {
            left_coeff: None,
            right_coeff: None,
            output_coeff: None,
        };
        // 2 * and = sum - xor
        let and = GenericGateSpec::Add {
            left_coeff: None,
            right_coeff: Some(-F::one()),
            output_coeff: Some(-F::two()),
        };
        let gates = vec![(Self::create_generic_gadget(Wire::for_row(new_row), sum, Some(and)))];

        (new_row + gates.len(), gates)
    }
}

/// Get the AND lookup table
pub fn lookup_table<F: PrimeField>() -> LookupTable<F> {
    lookup::tables::get_table::<F>(GateLookupTable::Xor)
}

/// Create a And for inputs as field elements starting at row 0
/// Input: first input, second input, and desired byte length
/// Panics if the input is too large for the chosen number of bytes
pub fn create_and_witness<F: PrimeField>(input1: F, input2: F, bytes: usize) -> [Vec<F>; COLUMNS] {
    let input1_big = input1.to_biguint();
    let input2_big = input2.to_biguint();
    if bytes * 8 < input1_big.bitlen() || bytes * 8 < input2_big.bitlen() {
        panic!("Bytes must be greater or equal than the inputs length");
    }

    // Compute BigUint output of AND, XOR
    let big_and = BigUint::bitwise_and(&input1_big, &input2_big, bytes);
    let big_xor = BigUint::bitwise_xor(&input1_big, &input2_big);
    // Transform BigUint values to field elements
    let xor = big_xor.to_field().unwrap();
    let and = big_and.to_field().unwrap();
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

/// Extends an AND witness to the whole witness
/// Input: first input, second input, and desired byte length
/// Panics if the input is too large for the chosen number of bytes
pub fn extend_and_witness<F: PrimeField>(
    witness: &mut [Vec<F>; COLUMNS],
    input1: F,
    input2: F,
    bytes: usize,
) {
    let and_witness = create_and_witness(input1, input2, bytes);
    for col in 0..COLUMNS {
        witness[col].extend(and_witness[col].iter());
    }
}
