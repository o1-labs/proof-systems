//! This module includes the definition of the XOR gadget for 64, 32, and 16 bits,
//! the definition of the constraints of the `Xor16` circuit gate,
//! and the code for witness generation for the XOR gadget.
use crate::{
    circuits::{
        argument::{Argument, ArgumentEnv, ArgumentType},
        berkeley_columns::BerkeleyChallengeTerm,
        expr::{constraints::ExprOps, Cache},
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
use ark_ff::PrimeField;
use core::{array, marker::PhantomData};
use num_bigint::BigUint;
use o1_utils::{BigUintFieldHelpers, BigUintHelpers, BitwiseOps, FieldHelpers};

use super::generic::GenericGateSpec;

impl<F: PrimeField> CircuitGate<F> {
    /// Extends a XOR gadget for `bits` length to a circuit
    ///
    /// Includes:
    /// - num_xors Xor16 gates
    /// - 1 Generic gate to constrain the final row to be zero with itself
    ///
    /// Input:
    /// - gates     : vector of circuit gates
    /// - bits      : length of the XOR gadget
    ///
    /// Output:
    /// - new row index
    pub fn extend_xor_gadget(gates: &mut Vec<Self>, bits: usize) -> usize {
        let new_row = gates.len();
        let (_, mut xor_gates) = Self::create_xor_gadget(new_row, bits);
        // extend the whole circuit with the xor gadget
        gates.append(&mut xor_gates);

        // check fin_in1, fin_in2, fin_out are zero
        let zero_row = gates.len() - 1;
        gates.connect_cell_pair((zero_row, 0), (zero_row, 1));
        gates.connect_cell_pair((zero_row, 0), (zero_row, 2));

        gates.len()
    }

    /// Creates a XOR gadget for `bits` length
    ///
    /// Includes:
    /// - num_xors Xor16 gates
    /// - 1 Generic gate to constrain the final row to be zero with itself
    ///
    /// Input:
    /// - new_row   : row to start the XOR gadget
    /// - bits      : number of bits in the XOR
    ///   Outputs tuple (next_row, circuit_gates) where
    /// - next_row  : next row after this gate
    /// - gates     : vector of circuit gates comprising this gate
    ///
    /// Warning:
    /// - don't forget to check that the final row is all zeros as in
    ///   `extend_xor_gadget`
    pub fn create_xor_gadget(new_row: usize, bits: usize) -> (usize, Vec<Self>) {
        let num_xors = num_xors(bits);
        let mut xor_gates = (0..num_xors)
            .map(|i| CircuitGate {
                typ: GateType::Xor16,
                wires: Wire::for_row(new_row + i),
                coeffs: vec![],
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

//~ `Xor16` - Chainable XOR constraints for words of multiples of 16 bits.
//~
//~ * This circuit gate is used to constrain that `in1` xored with `in2` equals `out`
//~ * The length of `in1`, `in2` and `out` must be the same and a multiple of 16bits.
//~ * This gate operates on the `Curr` and `Next` rows.
//~
//~ It uses three different types of constraints:
//~
//~ * copy          - copy to another cell (32-bits)
//~ * plookup       - xor-table plookup (4-bits)
//~ * decomposition - the constraints inside the gate
//~
//~ The 4-bit nybbles are assumed to be laid out with `0` column being the least significant nybble.
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
//~ to obtain a gadget for 64-bit words XOR:
//~
//~ | Row | `CircuitGate` | Purpose                                    |
//~ | --- | ------------- | ------------------------------------------ |
//~ |   0 | `Xor16`       | Xor 2 least significant bytes of the words |
//~ |   1 | `Xor16`       | Xor next 2 bytes of the words              |
//~ |   2 | `Xor16`       | Xor next 2 bytes of the words              |
//~ |   3 | `Xor16`       | Xor 2 most significant bytes of the words  |
//~ |   4 | `Generic`     | Zero values, can be reused as generic gate |
//~
//~ ```admonish info
//~ We could halve the number of rows of the 64-bit XOR gadget by having lookups
//~ for 8 bits at a time, but for now we will use the 4-bit XOR table that we have.
//~ Rough computations show that if we run 8 or more Keccaks in one circuit we should
//~ use the 8-bit XOR table.
//~ ```

#[derive(Default)]
pub struct Xor16<F>(PhantomData<F>);

impl<F> Argument<F> for Xor16<F>
where
    F: PrimeField,
{
    const ARGUMENT_TYPE: ArgumentType = ArgumentType::Gate(GateType::Xor16);
    const CONSTRAINTS: u32 = 3;

    // Constraints for Xor16
    //   * Operates on Curr and Next rows
    //   * Constrain the decomposition of `in1`, `in2` and `out` of multiples of 16 bits
    //   * The actual XOR is performed thanks to the plookups of 4-bit XORs.
    fn constraint_checks<T: ExprOps<F, BerkeleyChallengeTerm>>(
        env: &ArgumentEnv<F, T>,
        _cache: &mut Cache,
    ) -> Vec<T> {
        let two = T::from(2u64);
        // in1 = in1_0 + in1_1 * 2^4 + in1_2 * 2^8 + in1_3 * 2^12 + next_in1 * 2^16
        // in2 = in2_0 + in2_1 * 2^4 + in2_2 * 2^8 + in2_3 * 2^12 + next_in2 * 2^16
        // out = out_0 + out_1 * 2^4 + out_2 * 2^8 + out_3 * 2^12 + next_out * 2^16
        (0..3)
            .map(|i| {
                env.witness_curr(3 + 4 * i)
                    + env.witness_curr(4 + 4 * i) * two.clone().pow(4)
                    + env.witness_curr(5 + 4 * i) * two.clone().pow(8)
                    + env.witness_curr(6 + 4 * i) * two.clone().pow(12)
                    + two.clone().pow(16) * env.witness_next(i)
                    - env.witness_curr(i)
            })
            .collect::<Vec<T>>()
    }
}

// Witness layout
fn layout<F: PrimeField>(curr_row: usize, bits: usize) -> Vec<Vec<Box<dyn WitnessCell<F>>>> {
    let num_xor = num_xors(bits);
    let mut layout = (0..num_xor)
        .map(|i| xor_row(i, curr_row + i))
        .collect::<Vec<_>>();
    layout.push(zero_row());
    layout
}

fn xor_row<F: PrimeField>(nybble: usize, curr_row: usize) -> Vec<Box<dyn WitnessCell<F>>> {
    let start = nybble * 16;
    vec![
        VariableBitsCell::create("in1", start, None),
        VariableBitsCell::create("in2", start, None),
        VariableBitsCell::create("out", start, None),
        CopyBitsCell::create(curr_row, 0, 0, 4), // First 4-bit nybble of in1
        CopyBitsCell::create(curr_row, 0, 4, 8), // Second 4-bit nybble of in1
        CopyBitsCell::create(curr_row, 0, 8, 12), // Third 4-bit nybble of in1
        CopyBitsCell::create(curr_row, 0, 12, 16), // Fourth 4-bit nybble of in1
        CopyBitsCell::create(curr_row, 1, 0, 4), // First 4-bit nybble of in2
        CopyBitsCell::create(curr_row, 1, 4, 8), // Second 4-bit nybble of in2
        CopyBitsCell::create(curr_row, 1, 8, 12), // Third 4-bit nybble of in2
        CopyBitsCell::create(curr_row, 1, 12, 16), // Fourth 4-bit nybble of in2
        CopyBitsCell::create(curr_row, 2, 0, 4), // First 4-bit nybble of out
        CopyBitsCell::create(curr_row, 2, 4, 8), // Second 4-bit nybble of out
        CopyBitsCell::create(curr_row, 2, 8, 12), // Third 4-bit nybble of out
        CopyBitsCell::create(curr_row, 2, 12, 16), // Fourth 4-bit nybble of out
    ]
}

fn zero_row<F: PrimeField>() -> Vec<Box<dyn WitnessCell<F>>> {
    vec![
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
) {
    let xor_rows = layout(curr_row, bits);

    witness::init(
        witness,
        curr_row,
        &xor_rows,
        &variable_map!["in1" => words.0, "in2" => words.1, "out" => words.2],
    )
}

/// Extends the Xor rows to the full witness
/// Panics if the words are larger than the desired bits
pub fn extend_xor_witness<F: PrimeField>(
    witness: &mut [Vec<F>; COLUMNS],
    input1: F,
    input2: F,
    bits: usize,
) {
    let xor_witness = create_xor_witness(input1, input2, bits);
    for col in 0..COLUMNS {
        witness[col].extend(xor_witness[col].iter());
    }
}

/// Create a Xor for up to the native length starting at row 0
/// Input: first input and second input, bits length, current row
/// Panics if the desired bits is smaller than the inputs length
pub fn create_xor_witness<F: PrimeField>(input1: F, input2: F, bits: usize) -> [Vec<F>; COLUMNS] {
    let input1_big = input1.to_biguint();
    let input2_big = input2.to_biguint();
    if bits < input1_big.bitlen() || bits < input2_big.bitlen() {
        panic!("Bits must be greater or equal than the inputs length");
    }
    let output = BigUint::bitwise_xor(&input1_big, &input2_big);

    let mut xor_witness: [Vec<F>; COLUMNS] =
        array::from_fn(|_| vec![F::zero(); 1 + num_xors(bits)]);

    init_xor(
        &mut xor_witness,
        0,
        bits,
        (input1, input2, output.to_field().unwrap()),
    );

    xor_witness
}

/// Returns the number of XOR rows needed for inputs of usize bits
pub fn num_xors(bits: usize) -> usize {
    (bits as f64 / 16.0).ceil() as usize
}
