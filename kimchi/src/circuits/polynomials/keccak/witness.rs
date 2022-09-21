//! Foreign field multiplication witness computation

use crate::circuits::{
    polynomial::COLUMNS,
    polynomials::range_check::witness::{
        handle_standard_witness_cell, init_range_check_row, LimbWitnessCell, WitnessCell,
        ZeroWitnessCell,
    },
};
use ark_ff::PrimeField;
use std::array;

const fn xor_row(row: usize, offset: usize) -> [WitnessCell; COLUMNS] {
    [
        LimbWitnessCell::create(0, 0, 0 + offset, 32 + offset), // in1
        ZeroWitnessCell::create(),
        ZeroWitnessCell::create(),
        LimbWitnessCell::create(row + 1, 1, 0, 4),  // in2_0
        LimbWitnessCell::create(row + 1, 1, 4, 8),  // in2_1
        LimbWitnessCell::create(row + 1, 1, 8, 12), // in2_2
        LimbWitnessCell::create(row + 1, 1, 12, 16), // in2_3
        LimbWitnessCell::create(row, 0, 0, 4),      // in1_0
        LimbWitnessCell::create(row, 0, 4, 8),      // in1_1
        LimbWitnessCell::create(row, 0, 8, 12),     // in1_2
        LimbWitnessCell::create(row, 0, 12, 16),    // in1_3
        LimbWitnessCell::create(row + 1, 0, 0, 4),  // out_0
        LimbWitnessCell::create(row + 1, 0, 4, 8),  // out_1
        LimbWitnessCell::create(row + 1, 0, 8, 12), // out_2
        LimbWitnessCell::create(row + 1, 0, 12, 16), // out_3
    ]
}

const fn zero_row(row: usize, offset: usize) -> [WitnessCell; COLUMNS] {
    [
        LimbWitnessCell::create(1, 0, offset, offset + 32), // out
        LimbWitnessCell::create(2, 0, offset, offset + 32), // in2
        ZeroWitnessCell::create(),
        LimbWitnessCell::create(row + 1, 1, 16, 20), // in2_8
        LimbWitnessCell::create(row + 1, 1, 20, 24), // in2_9
        LimbWitnessCell::create(row + 1, 1, 24, 28), // in2_10
        LimbWitnessCell::create(row + 1, 1, 28, 32), // in2_11
        LimbWitnessCell::create(row, 0, 16, 20),     // in1_8
        LimbWitnessCell::create(row, 0, 20, 24),     // in1_9
        LimbWitnessCell::create(row, 0, 24, 28),     // in1_10
        LimbWitnessCell::create(row, 0, 28, 32),     // in1_11
        LimbWitnessCell::create(row + 1, 0, 16, 20), // out_8
        LimbWitnessCell::create(row + 1, 0, 20, 24), // out_9
        LimbWitnessCell::create(row + 1, 0, 24, 28), // out_10
        LimbWitnessCell::create(row + 1, 0, 28, 32), // out_11
    ]
}

// Witness layout
//   * The values of the crumbs appear with the least significant crumb first
//     but with big endian ordering of the bits inside the 32/64 element.
//   * The first column of the XOR row and the first and second columns of the
//     Zero rows must be instantiated before the rest, otherwise they copy 0.
//
const fn xor_rows(row: usize) -> [[WitnessCell; COLUMNS]; 4] {
    // TODO: determine where they come from -> full row and col
    // TODO: new more automated pattern for the 4-bit crumbs
    [
        // XOR row low
        xor_row(row, 0),
        // Zero row low
        zero_row(row, 0),
        // XOR row low
        xor_row(row + 2, 32),
        // Zero row low
        zero_row(row + 2, 32),
    ]
}

fn init_keccak_xor_rows<F: PrimeField>(witness: &mut [Vec<F>; COLUMNS], curr_row: usize) {
    let xor_rows = xor_rows(curr_row); // TODO: determine where they come from -> full row and col

    // First, the two first columns
    for (i, wit) in xor_rows.iter().enumerate() {
        for col in 0..2 {
            handle_standard_witness_cell(witness, &wit[col], curr_row + i, col, F::zero())
        }
    }
    for (i, wit) in xor_rows.iter().enumerate() {
        for col in 2..COLUMNS {
            handle_standard_witness_cell(witness, &wit[col], curr_row + i, col, F::zero())
        }
    }
}

/// Create a foreign field multiplication witness
/// Input: multiplicands left_input and right_input
pub fn create_witness<F: PrimeField>(input1: u64, input2: u64) -> [Vec<F>; COLUMNS] {
    let mut witness = array::from_fn(|_| vec![F::zero(); 0]);

    let output = input1 ^ input2;

    // TODO: range check of 64 bits? how to check that first sublimb is all zero here?
    init_range_check_row(&mut witness, 0, input1.into());
    init_range_check_row(&mut witness, 1, input2.into());
    init_range_check_row(&mut witness, 2, output.into());

    init_keccak_xor_rows(&mut witness, 3);
    witness
}
