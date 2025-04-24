//! This module includes the definition of the NOT gadget and the witness code generation,
//! for both the implementation running with `Xor16` gates and the one with `Generic` gates.
//! Note that this module does not include a `Not` gate type.
use super::{
    generic::GenericGateSpec,
    xor::{init_xor, num_xors},
};
use crate::circuits::{
    gate::{CircuitGate, Connect, GateType},
    polynomial::COLUMNS,
    wires::Wire,
};
use ark_ff::PrimeField;
use core::{array, cmp::max};
use num_bigint::BigUint;
use o1_utils::{BigUintHelpers, BitwiseOps, FieldHelpers};

//~ We implement NOT, i.e. bitwise negation, as a gadget in two different ways, needing no new gate type for it. Instead, it reuses the XOR gadget and the Generic gate.
//~
//~ The first version of the NOT gadget reuses `Xor16` by making the following observation: *the bitwise NOT operation is equivalent to the
//~ bitwise XOR operation with the all one words of a certain length*. In other words,
//~ $$\neg x = x \oplus 1^*$$
//~ where $1^*$ denotes a bitstring of all ones of length $|x|$. Let $x_i$ be the $i$-th bit of $x$, the intuition is that if $x_i = 0$ then
//~ XOR with $1$ outputs $1$, thus negating $x_i$. Similarly, if $x_i = 1$ then XOR with 1 outputs 0, again negating $x_i$. Thus, bitwise XOR
//~ with $1^*$ is equivalent to bitwise negation (i.e. NOT).
//~
//~ Then, if we take the XOR gadget with a second input to be the all one word of the same length, that gives us the NOT gadget.
//~ The correct length can be imposed by having a public input containing the `2^bits - 1` value and wiring it to the second input of the XOR gate.
//~ This approach needs as many rows as an XOR would need, for a single negation, but it comes with the advantage of making sure the input is of a certain length.
//~
//~ The other approach can be more efficient if we already know the length of the inputs. For example, the input may be the input of a range check gate,
//~ or the output of a previous XOR gadget (which will be the case in our Keccak usecase).
//~ In this case, we simply perform the negation as a subtraction of the input word from the all one word (which again can be copied from a public input).
//~ This comes with the advantage of holding up to 2 word negations per row (an eight-times improvement over the XOR approach), but it requires the user to know the length of the input.
//~
//~ ##### NOT Layout using XOR
//~
//~ Here we show the layout of the NOT gadget using the XOR approach. The gadget needs a row with a public input containing the all-one word of the given length. Then, a number of XORs
//~ follow, and a final `Zero` row is needed. In this case, the NOT gadget needs $\ceil(\frac{|x|}{16})$ `Xor16` gates, that means one XOR row for every 16 bits of the input word.
//~
//~ | Row       | `CircuitGate` | Purpose                                                               |
//~ | --------- | ------------- | --------------------------------------------------------------------- |
//~ | pub       | `Generic`     | Leading row with the public $1^*$ value                               |
//~ | i...i+n-1 | `Xor16`       | Negate every 4 nybbles of the word, from least to most significant    |
//~ | i+n       | `Generic`     | Constrain that the final row is all zeros for correctness of Xor gate |
//~
//~ ##### NOT Layout using Generic gates
//~
//~ Here we show the layout of the NOT gadget using the Generic approach. The gadget needs a row with a public input containing the all-one word of the given length, exactly as above.
//~ Then, one Generic gate reusing the all-one word as left inputs can be used to negate up to two words per row. This approach requires that the input word is known (or constrained)
//~ to have a given length.
//~
//~ | Row | `CircuitGate` | Purpose                                                                       |
//~ | --- | ------------- | ----------------------------------------------------------------------------- |
//~ | pub | `Generic`     | Leading row with the public $1^*$ value                                       |
//~ | i   | `Generic`     | Negate one or two words of the length given by the length of the all-one word |
//~
impl<F: PrimeField> CircuitGate<F> {
    /// Extends a bitwise negation gadget with `n` NOT components of some length
    /// previously constrained using a generic gate (checking that a cell stores
    /// `2^bits-1` value).
    /// Assumes that the inputs are known to have at most `bits` length.
    /// Starts the gates in the `new_row` position.
    ///
    /// Includes:
    /// - ceil(n/2) Double Generic gates to perform the `( 2^(bits) - 1 ) -
    ///   input` operation for every two inputs in each row
    ///
    /// Input:
    /// - gates     : full circuit
    /// - n         : number of negations to perform
    /// - pub_row   : row containing the public input with the all-one word of the given length
    ///
    /// Important:
    /// - If the bit length of the input is not fixed, then it must be
    ///   constrained somewhere else.
    /// - Otherwise, use the `extend_neg_checked_length` instead (but this one
    ///   requires about 8 times more rows).
    ///
    /// Warning:
    /// - don't forget to include a public input in `pub_row` to constrain the
    ///   left of each generic gate for negation to be `2^bits - 1`
    pub fn extend_not_gadget_unchecked_length(
        gates: &mut Vec<Self>,
        n: usize,
        pub_row: usize,
    ) -> usize {
        // taking advantage of double generic gates to negate two words in each row
        let mut new_row = gates.len();
        for _ in 0..(n / 2) {
            new_row = Self::extend_not_gnrc(gates, pub_row, new_row, true);
        }
        // odd number of NOTs require one more row to negate the last word only
        if n % 2 == 1 {
            new_row = Self::extend_not_gnrc(gates, pub_row, new_row, false);
        }
        new_row
    }

    // Extends a double generic gate for negation for one or two words
    // Input:
    // - gates          : full circuit to which the not will be added
    // - new_row        : row to start the double NOT generic gate
    // - pub_row        : row where the public inputs is stored (the 2^bits - 1) value (in the column 0 of that row)
    // - double_generic : whether to perform two NOTs or only one inside the generic gate
    // Output:
    // - new_row : next row after the double NOT generic gate, corresponds to `new_row+1`
    fn extend_not_gnrc(
        gates: &mut Vec<Self>,
        pub_row: usize,
        new_row: usize,
        double_generic: bool,
    ) -> usize {
        let g1 = GenericGateSpec::Add {
            left_coeff: None,
            right_coeff: Some(-F::one()),
            output_coeff: None,
        };
        let g2 = {
            if double_generic {
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
        if double_generic {
            gates.connect_cell_pair((pub_row, 0), (new_row, 3));
        }
        new_row + 1
    }

    /// Extends a NOT gadget for `bits` length using Xor gates.
    /// It implicitly constrains the length of the input to be at most 16 * num_xors bits.
    /// Includes:
    /// - num_xors Xor16 gates
    /// - 1 Generic gate to constrain the final row to be zero with itself
    ///   Input:
    /// - gates : full circuit
    /// - pub_row : row containing the public input with the all-one word of the given length
    /// - bits    : number of bits of the input
    ///   Precndition:
    /// - 1 initial public input generic gate in `all_ones_row` to constrain the input to be `2^bits-1`.
    ///   Warning:
    /// - don't forget to connect the left input to a public input row containing the `2^bits - 1` value
    pub fn extend_not_gadget_checked_length(
        gates: &mut Vec<Self>,
        all_ones_row: usize,
        bits: usize,
    ) -> usize {
        let n = num_xors(bits);
        let new_row = gates.len();
        let mut not_gates = (0..n)
            .map(|i| CircuitGate {
                typ: GateType::Xor16,
                wires: Wire::for_row(new_row + i),
                coeffs: vec![],
            })
            .collect::<Vec<_>>();
        let zero_row = new_row + n;
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
        gates.connect_cell_pair((all_ones_row, 0), (new_row, 1)); // input2 of xor is all ones

        gates.len()
    }
}

/// Extend a NOT witness for less than 255 bits (native field)
/// Input: full witness, first input and optional bit length
/// If `bits` is not provided, the negation is performed using the length of the `input` in bits.
/// If `bits` is provided, the negation takes the maximum length between `bits` and that of `input`.
/// Warning:
/// - don't forget to set a row of the witness with public input `2^bits -1` and wire it to the second input of the first `Xor16` gate
pub fn extend_not_witness_checked_length<F: PrimeField>(
    witness: &mut [Vec<F>; COLUMNS],
    input: F,
    bits: Option<usize>,
) {
    let input = input.to_biguint();
    let output = BigUint::bitwise_not(&input, bits);
    let bits = max(input.bitlen(), bits.unwrap_or(0));
    let mut not_witness: [Vec<F>; COLUMNS] =
        array::from_fn(|_| vec![F::zero(); num_xors(bits) + 1]);
    init_xor(
        &mut not_witness,
        0,
        bits,
        (
            F::from_biguint(&input).unwrap(),
            F::from(2u8).pow([bits as u64]) - F::one(),
            F::from_biguint(&output).unwrap(),
        ),
    );

    for col in 0..COLUMNS {
        witness[col].extend(not_witness[col].iter());
    }
}

/// Extends negation witnesses from generic gate, assuming the input witness already contains
/// public input rows holding the 2^bits-1 value.
/// Input: a vector of words to be negated, and the number of bits (all the same)
/// Returns error if the bits length is too small for the inputs
/// Warning: Set public input of bits in public generic gate
/// Note: `witness[0][pub] = 2^bits - 1`
pub fn extend_not_witness_unchecked_length<F: PrimeField>(
    witness: &mut [Vec<F>; COLUMNS],
    inputs: &[F],
    bits: usize,
) -> Result<(), String> {
    // Check inputs fit in bits and in native field
    let inputs = inputs
        .iter()
        .map(|input| input.to_biguint())
        .collect::<Vec<_>>();
    for input in inputs.clone() {
        if bits < input.bitlen() {
            Err(format!(
                "Bits must be greater or equal than the inputs length: {} < {}",
                bits,
                input.bitlen()
            ))?;
        }
    }
    let all_ones = F::from(2u8).pow([bits as u64]) - F::one();
    let rows = (inputs.len() as f64 / 2.0).ceil() as usize;
    let mut not_witness: [Vec<F>; COLUMNS] = array::from_fn(|_| vec![F::zero(); rows]);
    for (i, input) in inputs.iter().enumerate().step_by(2) {
        let row = i / 2;
        // fill in first NOT
        let negated_input1 = all_ones - F::from_biguint(input).unwrap();
        not_witness[0][row] = all_ones;
        not_witness[1][row] = F::from_biguint(input).unwrap();
        not_witness[2][row] = negated_input1;
        // Next element exists
        if i < inputs.len() - 1 {
            let next = &inputs[i + 1];
            // fill in second NOT
            let negated_input2 = all_ones - F::from_biguint(next).unwrap();
            not_witness[3][row] = all_ones;
            not_witness[4][row] = F::from_biguint(next).unwrap();
            not_witness[5][row] = negated_input2;
        }
    }
    for col in 0..COLUMNS {
        witness[col].extend(not_witness[col].iter());
    }
    Ok(())
}
