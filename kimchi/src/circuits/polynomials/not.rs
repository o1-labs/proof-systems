//! This module includes the definition of the NOT gadget and the witness code generation,
//! for both the implementation running with `Xor16` gates and the one with `Generic` gates.
//! Note that this module does not include a `Not` gate type.
use crate::circuits::{
    gate::{CircuitGate, Connect, GateType},
    polynomial::COLUMNS,
    wires::Wire,
};
use ark_ff::PrimeField;
use num_bigint::BigUint;
use o1_utils::{big_bits, BitOps, FieldHelpers};
use std::{array, cmp::max};

use super::{
    generic::GenericGateSpec,
    xor::{init_xor, num_xors},
};

//~ We implement the NOT gadget making use of the XOR gadget and the Generic gate, in two different ways. A new gate type is not needed.
//~
//~ The first version of the NOT gadget reuses `Xor16` by making the following observation:
//~ $$\textit{the bitwise NOT operation is equivalent to the bitwise XOR operation with the all one words of a certain length}$$
//~ Then, if we take the XOR gadget with a second input to be the all one word of the same length, that gives us the NOT gadget.
//~ The correct length can be imposed by having a public input containing the `2^bits - 1` value and wiring it to the second input of the XOR gate.
//~ This approach needs as many rows as a XOR would need, for a single negation, but it comes with the advantage of making sure the input is of a certain length.
//~
//~ The other approach can be more efficient if we already know the length of the inputs. For example, the input may be the input of a range check gate,
//~ or the output of a previous XOR gadget (which will be the case in our Keccak usecase).
//~ In this case, we simply perform the negation as a subtraction of the input word from the all one word (which again can be copied from a public input).
//~ This comes with the advantage of holding up to 2 word negations per row (an eight-times improvement over the XOR approach), but it requires the user to know the length of the input.

impl<F: PrimeField> CircuitGate<F> {
    /// Creates a negation gadget with `nots` NOT components of some length previously constrained using a generic gate
    /// (checking that a cell stores `2^bits-1` value). Assumes that the inputs are known to have at most `bits` length.
    /// Starts the gates in the `new_row` position.
    /// Includes:
    /// - ceil(nots/2) Double Generic gates to perform the `( 2^(bits) - 1 ) - input` operation for every two inputs in each row
    /// BEWARE:
    /// - If the input is not known to have at most `bits` length, this should be constrained somewhere else.
    /// - Otherwise, use the Xor builder instead (but this one requires about 8 times more rows).
    /// INTEGRATION:
    /// - Needs a leading public input generic gate in `pub_row` to constrain the left input of each generic gate for negation to be `2^bits-1`.
    pub fn extend_not_gnrc_gadget(
        gates: &mut Vec<Self>,
        nots: usize,
        pub_row: usize,
        new_row: usize,
    ) -> usize {
        // taking advantage of double generic gates to negate two words in each row
        let mut new_row = new_row;
        for _ in 0..nots / 2 {
            new_row = Self::not_gnrc(gates, pub_row, new_row, true);
        }
        // odd number of NOTs require one more row to negate the last word only
        if nots % 2 == 1 {
            new_row = Self::not_gnrc(gates, pub_row, new_row, false);
        }
        new_row
    }

    // Returns a double generic gate for negation for one or two words
    // Input:
    // - new_row : row to start the double NOT generic gate
    // - pub_row : row where the public inputs is stored (the 2^bits - 1) value (in the column 0 of that row)
    // - double  : whether to perform two NOTs or only one inside the generic gate
    // Output:
    // - new_row : next row after the double NOT generic gate, corresponds to `new_row+1`
    fn not_gnrc(gates: &mut Vec<Self>, pub_row: usize, new_row: usize, double: bool) -> usize {
        let g1 = GenericGateSpec::Add {
            left_coeff: None,
            right_coeff: Some(-F::one()),
            output_coeff: None,
        };
        let g2 = {
            if double {
                Some(GenericGateSpec::Add {
                    left_coeff: None,
                    right_coeff: Some(-F::one()),
                    output_coeff: None,
                })
            } else {
                None
            }
        };
        let mut not_gate = vec![CircuitGate::create_generic_gadget(
            Wire::for_row(new_row),
            g1,
            g2,
        )];
        gates.append(&mut not_gate);
        // check left inputs of the double generic gate correspond to the 2^bits - 1 value
        gates.connect_cell_pair((pub_row, 0), (new_row, 0));
        if double {
            gates.connect_cell_pair((pub_row, 0), (new_row, 3));
        }
        new_row + 1
    }

    /// Creates a NOT gadget for `bits` length using Xor gates.
    /// It implicitly constrains the length of the input to be at most 16 * num_xors bits.
    /// Includes:
    /// - num_xors Xor16 gates
    /// - 1 Generic gate to constrain the final row to be zero with itself
    /// Input:
    /// - new_row : row to start the NOT gadget
    /// Requires:
    /// - 1 initial public input generic gate in `pub_row` to constrain the input to be `2^bits-1`.
    /// INTEGRATION:
    /// - Connect the left input to a public input row containing the 2^bits-1 value
    pub fn extend_not_xor_gadget(
        gates: &mut Vec<Self>,
        pub_row: usize,
        new_row: usize,
        bits: usize,
    ) -> usize {
        let num_xors = num_xors(bits);
        let mut not_gates = (0..num_xors)
            .map(|i| CircuitGate {
                typ: GateType::Xor16,
                wires: Wire::for_row(new_row + i),
                coeffs: vec![],
            })
            .collect::<Vec<_>>();
        let zero_row = new_row + num_xors;
        not_gates.push(CircuitGate::create_generic_gadget(
            Wire::for_row(zero_row),
            GenericGateSpec::Const(F::zero()),
            None,
        ));
        gates.extend(not_gates);
        // check fin_in1, fin_in2, fin_out are zero
        gates.connect_cell_pair((zero_row, 0), (zero_row, 1));
        gates.connect_cell_pair((zero_row, 0), (zero_row, 2));
        // Integration
        gates.connect_cell_pair((pub_row, 0), (new_row, 1)); // input2 of xor is all ones

        gates.len()
    }
}

/// Create a Not for less than 255 bits (native field) starting at row 0
/// Input: first input and second input
pub fn create_not_xor_witness<F: PrimeField>(input: F, bits: Option<usize>) -> [Vec<F>; COLUMNS] {
    let input = input.to_biguint();
    let output = BigUint::bitnot(&input, bits);
    let bits = max(big_bits(&input), bits.unwrap_or(0));
    let mut not_witness: [Vec<F>; COLUMNS] =
        array::from_fn(|_| vec![F::zero(); num_xors(bits) + 1]);
    init_xor(
        &mut not_witness,
        0,
        bits,
        (
            F::from_biguint(&input).unwrap(),
            F::from(2u8).pow(&[bits as u64]) - F::one(),
            F::from_biguint(&output).unwrap(),
        ),
    );

    not_witness
}

/// Creates as many negations as the number of inputs. The inputs must fit in the native field.
/// We start at the row 0 using generic gates to perform the negations.
/// Input: a vector of words to be negated, and the number of bits (all the same)
/// Panics if the bits length is too small for the inputs
/// INTEGRATION: Set public input of bits in public generic gate
/// TODO: `witness[0][pub] = 2^bits - 1`
pub fn create_not_gnrc_witness<F: PrimeField>(inputs: &[F], bits: usize) -> [Vec<F>; COLUMNS] {
    // Check inputs fit in bits and in native field
    let inputs = inputs
        .iter()
        .map(|input| input.to_biguint())
        .collect::<Vec<_>>();
    for input in inputs.clone() {
        if bits < big_bits(&input) {
            panic!("Bits must be greater or equal than the inputs length");
        }
    }
    let all_ones = F::from(2u8).pow(&[bits as u64]) - F::one();
    let rows = (inputs.len() as f64 / 2.0).ceil() as usize;
    let mut not_witness = array::from_fn(|_| vec![F::zero(); rows]);
    for (i, input) in inputs.iter().enumerate().step_by(2) {
        let row = i / 2;
        // fill in first NOT
        let not1 = all_ones - F::from_biguint(input).unwrap();
        not_witness[0][row] = all_ones;
        not_witness[1][row] = F::from_biguint(input).unwrap();
        not_witness[2][row] = not1;
        // Next element exists
        if i < inputs.len() - 1 {
            let next = &inputs[i + 1];
            // fill in second NOT
            let not2 = all_ones - F::from_biguint(next).unwrap();
            not_witness[3][row] = all_ones;
            not_witness[4][row] = F::from_biguint(next).unwrap();
            not_witness[5][row] = not2;
        }
    }
    not_witness
}
