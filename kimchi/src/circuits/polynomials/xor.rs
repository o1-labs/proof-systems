//! This module includes the definition of the XOR gadget for 64, 32, and 16 bits,
//! the definition of the constraints of the `Xor` circuit gate,
//! and the code for witness generation for the XOR gadget.
use crate::{
    circuits::{
        argument::{Argument, ArgumentEnv, ArgumentType},
        expr::constraints::ExprOps,
        gate::{CircuitGate, Connect, GateType},
        lookup::{
            self,
            tables::{GateLookupTable, LookupTable},
        },
        polynomial::COLUMNS,
        wires::Wire,
        witness::{self, ConstantCell, CopyBitsCell, VariableBitsCell, Variables, WitnessCell},
    },
    variable_map,
};
use ark_ff::{PrimeField, SquareRootField};
use num_bigint::BigUint;
use o1_utils::{BigUintFieldHelpers, BigUintHelpers, BitwiseOps, FieldHelpers};
use std::{array, marker::PhantomData};

use super::generic::GenericGateSpec;

// Default length of the inputs for the Xor table
pub const XOR_LEN: usize = 4;

impl<F: PrimeField + SquareRootField> CircuitGate<F> {
    /// Extends a XOR gadget for `bits` length to a circuit
    /// Includes:
    /// - num_xors Xor gates
    /// - 1 Generic gate to constrain the final row to be zero with itself
    /// Input:
    /// - gates     : vector of circuit gates
    /// - bits      : length of the XOR gadget
    /// - n         : length of XOR lookup table (default: 4)
    /// Output:
    /// - new row index
    pub fn extend_xor_gadget(gates: &mut Vec<Self>, bits: usize, len_xor: Option<usize>) -> usize {
        let new_row = gates.len();
        let (_, mut xor_gates) = Self::create_xor_gadget(new_row, bits, len_xor);
        // extend the whole circuit with the xor gadget
        gates.append(&mut xor_gates);

        // check fin_in1, fin_in2, fin_out are zero
        let zero_row = gates.len() - 1;
        gates.connect_cell_pair((zero_row, 0), (zero_row, 1));
        gates.connect_cell_pair((zero_row, 0), (zero_row, 2));

        gates.len()
    }

    /// Creates a XOR gadget for `bits` length
    /// Includes:
    /// - num_xors Xor gates
    /// - 1 Generic gate to constrain the final row to be zero with itself
    /// Input:
    /// - new_row   : row to start the XOR gadget
    /// - bits      : number of bits in the XOR
    /// - n         : length of XOR lookup table (default: 4)
    /// Outputs tuple (next_row, circuit_gates) where
    /// - next_row  : next row after this gate
    /// - gates     : vector of circuit gates comprising this gate
    /// Warning:
    /// - don't forget to check that the final row is all zeros as in `extend_xor_gadget`
    pub fn create_xor_gadget(
        new_row: usize,
        bits: usize,
        len_xor: Option<usize>,
    ) -> (usize, Vec<Self>) {
        let num_xors = num_xors(bits, len_xor);
        let mut xor_gates = (0..num_xors)
            .map(|i| CircuitGate {
                typ: GateType::Xor,
                wires: Wire::for_row(new_row + i),
                coeffs: vec![F::two_pow((len_xor.unwrap_or(XOR_LEN)) as u64)],
            })
            .collect::<Vec<_>>();
        let zero_row = new_row + num_xors;
        xor_gates.push(CircuitGate::create_generic_gadget(
            Wire::for_row(zero_row),
            GenericGateSpec::Const(F::zero()),
            None,
        ));

        (new_row + xor_gates.len(), xor_gates)
    }
}

/// Get the xor lookup table
pub fn lookup_table<F: PrimeField>() -> LookupTable<F> {
    lookup::tables::get_table::<F>(GateLookupTable::Xor)
}

//~ `Xor` - Chainable XOR constraints for words of multiples of N bits.
//~
//~ * This circuit gate is used to constrain that `in1` xored with `in2` equals `out`
//~ * The length of `in1`, `in2` and `out` must be the same and a multiple of N bits.
//~ * This gate operates on the `Curr` and `Next` rows.
//~
//~ It uses three different types of constraints:
//~
//~ * copy          - copy to another cell
//~ * plookup       - xor-table plookup (N bits)
//~ * decomposition - the constraints inside the gate
//~
//~ The N-bit nibbles are assumed to be laid out with `0` column being the least significant set of bits.
//~ Given values `in1`, `in2` and `out`, the layout looks like this:
//~
//~ | Column |          `Curr`  |          `Next`  |
//~ | ------ | ---------------- | ---------------- |
//~ |      0 | copy     `in1`   | copy     `in1'`  |
//~ |      1 | copy     `in2`   | copy     `in2'`  |
//~ |      2 | copy     `out`   | copy     `out'`  |
//~ |      3 | plookup0 `in1_0` |                  |
//~ |      4 | plookup1 `in1_1` |                  |
//~ |      5 | plookup2 `in1_2` |                  |
//~ |      6 | plookup3 `in1_3` |                  |
//~ |      7 | plookup0 `in2_0` |                  |
//~ |      8 | plookup1 `in2_1` |                  |
//~ |      9 | plookup2 `in2_2` |                  |
//~ |     10 | plookup3 `in2_3` |                  |
//~ |     11 | plookup0 `out_0` |                  |
//~ |     12 | plookup1 `out_1` |                  |
//~ |     13 | plookup2 `out_2` |                  |
//~ |     14 | plookup3 `out_3` |                  |
//~
//~ One single gate with next values of `in1'`, `in2'` and `out'` being zero can be used to check
//~ that the original `in1`, `in2` and `out` had 16-bits. We can chain this gate 4 times as follows
//~ to obtain a gadget for 64-bit words XOR. This assumes the lookup table being used is for 4 bits
//~ of Xor. This length is configured in the first coefficient of the gate.
//~
//~ | Row | `CircuitGate` | Purpose                                    |
//~ | --- | ------------- | ------------------------------------------ |
//~ |   0 | `Xor`         | Xor 4N least significant bits of the words |
//~ |   1 | `Xor`         | Xor next 4N bits of the words              |
//~ |   2 | `Xor`         | Xor next 4N bits of the words              |
//~ |   3 | `Xor`         | Xor 4N most significant bits of the words  |
//~ |   4 | `Generic`     | Zero values, can be reused as generic gate |
//~
//~ ```admonish info
//~ We could halve the number of rows of the 64-bit XOR gadget by having lookups
//~ for 8 bits at a time, but for now we will use the 4-bit XOR table that we have.
//~ Rough computations show that if we run 8 or more Keccaks in one circuit we should
//~ use the 8-bit XOR table.
//~ ```

#[derive(Default)]
pub struct Xor<F>(PhantomData<F>);

impl<F> Argument<F> for Xor<F>
where
    F: PrimeField,
{
    const ARGUMENT_TYPE: ArgumentType = ArgumentType::Gate(GateType::Xor);
    const CONSTRAINTS: u32 = 3;

    // Constraints for Xor
    //   * Operates on Curr and Next rows
    //   * Constrain the decomposition of `in1`, `in2` and `out` of multiples of 16 bits
    //   * The actual XOR is performed thanks to the plookups of 4-bit XORs.
    //   * The gate expects to have the value `2^N` in the first coefficient,
    //     where `N` is the number of bits of the lookup table for Xor
    //   * At the moment, `N` is 4, so one `Xor` gate can be used to XOR 16 bits
    fn constraint_checks<T: ExprOps<F>>(env: &ArgumentEnv<F, T>) -> Vec<T> {
        // in1 = in1_0 + in1_1 * 2^N + in1_2 * (2^N)^2 + in1_3 * (2^N)^3 + next_in1 * (2^N)^4
        // in2 = in2_0 + in2_1 * 2^N + in2_2 * (2^N)^2 + in2_3 * (2^N)^3 + next_in2 * (2^N)^4
        // out = out_0 + out_1 * 2^N + out_2 * (2^N)^2 + out_3 * (2^N)^3 + next_out * (2^N)^4
        (0..3)
            .map(|i| {
                env.witness_curr(3 + 4 * i)
                    + env.witness_curr(4 + 4 * i) * env.coeff(0) // 2^N
                    + env.witness_curr(5 + 4 * i) * env.coeff(0).pow(2) // (2^N)^2
                    + env.witness_curr(6 + 4 * i) * env.coeff(0).pow(3) // (2^N)^3
                    + env.witness_next(i) * env.coeff(0).pow(4) // (2^N)^4
                    - env.witness_curr(i)
            })
            .collect::<Vec<T>>()
    }
}

// Witness layout for current row, and total number of bits, n bits of Xor table (default 4)
fn layout<F: PrimeField>(
    curr_row: usize,
    bits: usize,
    len_xor: Option<usize>,
) -> Vec<[Box<dyn WitnessCell<F>>; COLUMNS]> {
    let num_xor = num_xors(bits, len_xor);
    let mut layout = (0..num_xor)
        .map(|i| xor_row(i, curr_row + i, len_xor))
        .collect::<Vec<_>>();
    layout.push(zero_row());
    layout
}

// Returns a Xor row for the corresponding set of `set * 4 * len_xor` bits where len_xor is the length of the lookup table of Xor.
// Right now, n = 4, so we can XOR 16 bits at a time.
fn xor_row<F: PrimeField>(
    set: usize,
    curr_row: usize,
    len_xor: Option<usize>,
) -> [Box<dyn WitnessCell<F>>; COLUMNS] {
    let len_xor = len_xor.unwrap_or(XOR_LEN);
    let start = set * 4 * len_xor;
    [
        VariableBitsCell::create("in1", start, None),
        VariableBitsCell::create("in2", start, None),
        VariableBitsCell::create("out", start, None),
        CopyBitsCell::create(curr_row, 0, 0, len_xor), // First n-bit string of in1
        CopyBitsCell::create(curr_row, 0, len_xor, 2 * len_xor), // Second n-bit string of in1
        CopyBitsCell::create(curr_row, 0, 2 * len_xor, 3 * len_xor), // Third n-bit string of in1
        CopyBitsCell::create(curr_row, 0, 3 * len_xor, 4 * len_xor), // Fourth n-bit string of in1
        CopyBitsCell::create(curr_row, 1, 0, len_xor), // First n-bit string of in2
        CopyBitsCell::create(curr_row, 1, len_xor, 2 * len_xor), // Second n-bit string of in2
        CopyBitsCell::create(curr_row, 1, 2 * len_xor, 3 * len_xor), // Third n-bit string of in2
        CopyBitsCell::create(curr_row, 1, 3 * len_xor, 4 * len_xor), // Fourth n-bit string of in2
        CopyBitsCell::create(curr_row, 2, 0, len_xor), // First n-bit string of out
        CopyBitsCell::create(curr_row, 2, len_xor, 2 * len_xor), // Second n-bit string of out
        CopyBitsCell::create(curr_row, 2, 2 * len_xor, 3 * len_xor), // Third n-bit string of out
        CopyBitsCell::create(curr_row, 2, 3 * len_xor, 4 * len_xor), // Fourth n-bit string of out
    ]
}

fn zero_row<F: PrimeField>() -> [Box<dyn WitnessCell<F>>; COLUMNS] {
    [
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
        ConstantCell::create(F::zero()),
        ConstantCell::create(F::zero()),
        ConstantCell::create(F::zero()),
    ]
}

pub(crate) fn init_xor<F: PrimeField>(
    witness: &mut [Vec<F>; COLUMNS],
    curr_row: usize,
    bits: usize,
    words: (F, F, F),
    len_xor: Option<usize>,
) {
    let xor_rows = layout(curr_row, bits, len_xor);

    witness::init(
        witness,
        curr_row,
        &xor_rows,
        &variable_map!["in1" => words.0, "in2" => words.1, "out" => words.2],
    )
}

/// Extends the Xor rows to the full witness
/// Panics if the words are larger than the desired bits
/// Input: witness, first input, second input, total bits length, length of Xor table
pub fn extend_xor_witness<F: PrimeField>(
    witness: &mut [Vec<F>; COLUMNS],
    input1: F,
    input2: F,
    bits: usize,
    len_xor: Option<usize>,
) {
    let xor_witness = create_xor_witness(input1, input2, bits, len_xor);
    for col in 0..COLUMNS {
        witness[col].extend(xor_witness[col].iter());
    }
}

/// Create a Xor for up to the native length starting at row 0
/// Input: first input and second input, total bits length, length of Xor table (4 if None)
/// Panics if the desired bits is smaller than the inputs length
pub fn create_xor_witness<F: PrimeField>(
    input1: F,
    input2: F,
    bits: usize,
    len_xor: Option<usize>,
) -> [Vec<F>; COLUMNS] {
    let input1_big = input1.to_biguint();
    let input2_big = input2.to_biguint();
    if bits < input1_big.bitlen() || bits < input2_big.bitlen() {
        panic!("Bits must be greater or equal than the inputs length");
    }
    let output = BigUint::bitwise_xor(&input1_big, &input2_big);

    let mut xor_witness: [Vec<F>; COLUMNS] =
        array::from_fn(|_| vec![F::zero(); 1 + num_xors(bits, len_xor)]);

    init_xor(
        &mut xor_witness,
        0,
        bits,
        (input1, input2, output.to_field().unwrap()),
        len_xor,
    );

    xor_witness
}

/// Returns the number of XOR rows needed for inputs of usize bits, for Xor table of n bits
pub fn num_xors(bits: usize, len_xor: Option<usize>) -> usize {
    (bits as f64 / (4.0 * (len_xor.unwrap_or(XOR_LEN) as f64))).ceil() as usize
}
