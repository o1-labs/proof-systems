//! This module includes the definition of the XOR gadget for 64, 32, and 16 bits,
//! the definition of the constraints of the `Xor16` circuit gate,
//! and the code for witness generation for the XOR gadget.
use crate::{
    circuits::{
        argument::{Argument, ArgumentEnv, ArgumentType},
        expr::constraints::ExprOps,
        gate::{CircuitGate, Connect, GateType},
        polynomial::COLUMNS,
        wires::Wire,
        witness::{self, ConstantCell, CopyBitsCell, CrumbCell, Variables, WitnessCell},
    },
    variable_map,
};
use ark_ff::PrimeField;
use std::{array, marker::PhantomData};

impl<F: PrimeField> CircuitGate<F> {
    /// Creates a XOR gadget for `bits` length
    /// Includes:
    /// - num_xors Xor16 gates
    /// - 1 Generic gate to constrain the final row to be zero with itself
    /// Outputs tuple (next_row, circuit_gates) where
    /// - next_row  : next row after this gate
    /// - gates     : vector of circuit gates comprising this gate
    pub fn create_xor(new_row: usize, bits: usize) -> (usize, Vec<Self>) {
        let num_xors = num_xors(bits);
        let mut gates = (0..num_xors)
            .map(|i| CircuitGate {
                typ: GateType::Xor16,
                wires: Wire::new(new_row + i),
                coeffs: vec![],
            })
            .collect::<Vec<_>>();
        let zero_row = new_row + num_xors;
        gates.push(CircuitGate {
            typ: GateType::Generic,
            wires: Wire::new(zero_row),
            coeffs: vec![],
        });
        // check fin_in1, fin_in2, fin_out are zero
        gates.connect_cell_pair((zero_row, 0), (zero_row, 1));
        gates.connect_cell_pair((zero_row, 1), (zero_row, 2));

        (zero_row + 1, gates)
    }
}

//~ ##### `Xor16` - Chainable XOR constraints for words of multiples of 16 bits.
//~
//~ * This circuit gate is used to constrain that `in1` xored with `in2` equals `out`
//~ * The length of `in1`, `in2` and `out` must be the same and a multiple of 16bits.
//~ * This gate operates on the `Curr` and `Next` rows.
//~
//~ It uses three different types of constraints
//~ * copy          - copy to another cell (32-bits)
//~ * plookup       - xor-table plookup (4-bits)
//~ * decomposition - the constraints inside the gate
//~
//~ The 4-bit crumbs are assumed to be laid out with `0` column being the least significant crumb.
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
//~  | Row | `CircuitGate` | Purpose                                    |
//~  | --- | ------------- | ------------------------------------------ |
//~  |   0 | `Xor16`       | Xor 2 least significant bytes of the words |
//~  |   1 | `Xor16`       | Xor next 2 bytes of the words              |
//~  |   2 | `Xor16`       | Xor next 2 bytes of the words              |
//~  |   3 | `Xor16`       | Xor 2 most significant bytes of the words  |
//~  |   4 | `Zero`        | Zero values, can be reused as generic gate |
//~
//~ ```admonition::notice
//~  We could half the number of rows of the 64-bit XOR gadget by having lookups
//~  for 8 bits at a time, but for now we will use the 4-bit XOR table that we have.
//~  Rough computations show that if we run 8 or more Keccaks in one circuit we should
//~  use the 8-bit XOR table.
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
    fn constraint_checks<T: ExprOps<F>>(env: &ArgumentEnv<F, T>) -> Vec<T> {
        // Returns the constraints:
        // in1 = in1_0 + in1_1 * 2^4 + in1_2 * 2^8 + in1_3 * 2^12 + next_in1 * 2^16
        // in2 = in2_0 + in2_1 * 2^4 + in2_2 * 2^8 + in2_3 * 2^12 + next_in2 * 2^16
        // out = out_0 + out_1 * 2^4 + out_2 * 2^8 + out_3 * 2^12 + next_out * 2^16
        (0..3)
            .map(|i| {
                env.witness_curr(i)
                    - quarter_sum(env, 3 + i)
                    - T::from(2u64).pow(16) * env.witness_next(i)
            })
            .collect::<Vec<T>>()
    }
}

/// Computes the decomposition of a 16-bit quarter-word whose least significant 4-bit crumb
/// is located in the `lsb` column of `witness_curr` as:
/// sum = crumb0 + crumb1 * 2^4 + crumb2 * 2^8 + crumb3 * 2^12
///
/// The layout is the following:
///
/// |        | lsb     | lsb + 3 | lsb + 6 | lsb + 9 |
/// | ------ | ------- | ------- | ------- | ------- |
/// | `Curr` |  crumb0 |  crumb1 |  crumb2 |  crumb3 |
///
fn quarter_sum<F: PrimeField, T: ExprOps<F>>(env: &ArgumentEnv<F, T>, lsb: usize) -> T {
    (0..4).fold(T::zero(), |mut sum, i| {
        sum += env.witness_curr(lsb + 3 * i) * T::from(2u64).pow(4 * i as u64);
        sum
    })
}

// Witness layout
//   * The values of the crumbs appear with the least significant crumb first
//     but with big endian ordering of the bits inside the 32/64 element.
//   * The first column of the XOR row and the first and second columns of the
//     Zero rows must be instantiated before the rest, otherwise they copy 0.
//
fn layout<F: PrimeField>(curr_row: usize, bits: usize) -> Vec<[Box<dyn WitnessCell<F>>; COLUMNS]> {
    let num_xor = num_xors(bits);
    let mut layout = (0..num_xor)
        .map(|i| xor_row(i, curr_row + i))
        .collect::<Vec<_>>();
    layout.push(zero_row());
    layout
}

fn xor_row<F: PrimeField>(crumb: usize, curr_row: usize) -> [Box<dyn WitnessCell<F>>; COLUMNS] {
    [
        CrumbCell::create("in1", crumb),
        CrumbCell::create("in2", crumb),
        CrumbCell::create("out", crumb),
        CopyBitsCell::create(curr_row, 0, 0, 4), // First 4-bit crumb of in1
        CopyBitsCell::create(curr_row, 1, 0, 4), // First 4-bit crumb of in2
        CopyBitsCell::create(curr_row, 2, 0, 4), // First 4-bit crumb of out
        CopyBitsCell::create(curr_row, 0, 4, 8), // Second 4-bit crumb of in1
        CopyBitsCell::create(curr_row, 1, 4, 8), // Second 4-bit crumb of in2
        CopyBitsCell::create(curr_row, 2, 4, 8), // Second 4-bit crumb of out
        CopyBitsCell::create(curr_row, 0, 8, 12), // Third 4-bit crumb of in1
        CopyBitsCell::create(curr_row, 1, 8, 12), // Third 4-bit crumb of in2
        CopyBitsCell::create(curr_row, 2, 8, 12), // Third 4-bit crumb of out
        CopyBitsCell::create(curr_row, 0, 12, 16), // Fourth 4-bit crumb of in1
        CopyBitsCell::create(curr_row, 1, 12, 16), // Fourth 4-bit crumb of in2
        CopyBitsCell::create(curr_row, 2, 12, 16), // Fourth 4-bit crumb of out
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

fn init_xor<F: PrimeField>(
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

/// Extends the xor rows to the full witness
pub fn extend_xor_rows<F: PrimeField>(
    witness: &mut [Vec<F>; COLUMNS],
    bits: usize,
    words: (F, F, F),
) {
    let xor_witness: [Vec<F>; COLUMNS] = array::from_fn(|_| vec![F::zero(); num_xors(bits) + 1]);
    let xor_row = witness[0].len();
    for col in 0..COLUMNS {
        witness[col].extend(xor_witness[col].iter());
    }
    init_xor(witness, xor_row, bits, words);
}

/// Create a keccak Xor for up to 128 bits
/// Input: first input and second input
pub fn create<F: PrimeField>(input1: u128, input2: u128, bits: usize) -> [Vec<F>; COLUMNS] {
    let output = input1 ^ input2;

    let mut xor_witness: [Vec<F>; COLUMNS] =
        array::from_fn(|_| vec![F::zero(); num_xors(bits) + 1]);
    init_xor(
        &mut xor_witness,
        0,
        bits,
        (F::from(input1), F::from(input2), F::from(output)),
    );

    xor_witness
}

/// Returns the number of XOR rows needed for inputs of usize bits
pub fn num_xors(bits: usize) -> usize {
    (bits as f64 / 16.0).ceil() as usize
}
