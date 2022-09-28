//! Foreign field multiplication witness computation

use crate::circuits::{
    polynomial::COLUMNS,
    polynomials::range_check::witness::{
        extend_single, handle_standard_witness_cell, CopyWitnessCell, LimbWitnessCell, WitnessCell,
        ZeroWitnessCell,
    },
};
use ark_ff::PrimeField;
use std::array;

const fn xor_row(rc_row: usize, curr_row: usize, offset: usize) -> [WitnessCell; COLUMNS] {
    [
        LimbWitnessCell::create(rc_row, 0, offset, 32 + offset), // in1
        ZeroWitnessCell::create(),
        ZeroWitnessCell::create(),
        LimbWitnessCell::create(curr_row + 1, 1, 0, 4), // in2_0
        LimbWitnessCell::create(curr_row + 1, 1, 4, 8), // in2_1
        LimbWitnessCell::create(curr_row + 1, 1, 8, 12), // in2_2
        LimbWitnessCell::create(curr_row + 1, 1, 12, 16), // in2_3
        LimbWitnessCell::create(curr_row, 0, 0, 4),     // in1_0
        LimbWitnessCell::create(curr_row, 0, 4, 8),     // in1_1
        LimbWitnessCell::create(curr_row, 0, 8, 12),    // in1_2
        LimbWitnessCell::create(curr_row, 0, 12, 16),   // in1_3
        LimbWitnessCell::create(curr_row + 1, 0, 0, 4), // out_0
        LimbWitnessCell::create(curr_row + 1, 0, 4, 8), // out_1
        LimbWitnessCell::create(curr_row + 1, 0, 8, 12), // out_2
        LimbWitnessCell::create(curr_row + 1, 0, 12, 16), // out_3
    ]
}

const fn zero_row(rc_row: usize, curr_row: usize, offset: usize) -> [WitnessCell; COLUMNS] {
    [
        LimbWitnessCell::create(rc_row + 2, 0, offset, offset + 32), // out
        LimbWitnessCell::create(rc_row + 1, 0, offset, offset + 32), // in2
        ZeroWitnessCell::create(),
        LimbWitnessCell::create(curr_row + 1, 1, 16, 20), // in2_8
        LimbWitnessCell::create(curr_row + 1, 1, 20, 24), // in2_9
        LimbWitnessCell::create(curr_row + 1, 1, 24, 28), // in2_10
        LimbWitnessCell::create(curr_row + 1, 1, 28, 32), // in2_11
        LimbWitnessCell::create(curr_row, 0, 16, 20),     // in1_8
        LimbWitnessCell::create(curr_row, 0, 20, 24),     // in1_9
        LimbWitnessCell::create(curr_row, 0, 24, 28),     // in1_10
        LimbWitnessCell::create(curr_row, 0, 28, 32),     // in1_11
        LimbWitnessCell::create(curr_row + 1, 0, 16, 20), // out_8
        LimbWitnessCell::create(curr_row + 1, 0, 20, 24), // out_9
        LimbWitnessCell::create(curr_row + 1, 0, 24, 28), // out_10
        LimbWitnessCell::create(curr_row + 1, 0, 28, 32), // out_11
    ]
}

// Witness layout
//   * The values of the crumbs appear with the least significant crumb first
//     but with big endian ordering of the bits inside the 32/64 element.
//   * The first column of the XOR row and the first and second columns of the
//     Zero rows must be instantiated before the rest, otherwise they copy 0.
//
const fn xor_rows(rc_row: usize, curr_row: usize) -> [[WitnessCell; COLUMNS]; 4] {
    // TODO: new more automated pattern for the 4-bit crumbs
    [
        // XOR row low
        xor_row(rc_row, curr_row, 0),
        // Zero row low
        zero_row(rc_row, curr_row, 0),
        // XOR row low
        xor_row(rc_row, curr_row + 2, 32),
        // Zero row low
        zero_row(rc_row, curr_row + 2, 32),
    ]
}

/// Initializes two rows of inputs pairs and one output value
fn init_keccak_bit_rows<F: PrimeField>(
    witness: &mut [Vec<F>; COLUMNS],
    rc_row: usize,
    xor_row: usize,
    bit_row: usize,
) {
    let bit_rows = [
        [
            CopyWitnessCell::create(rc_row, 0),      // 64 bit first input
            CopyWitnessCell::create(xor_row, 0),     // 32 bit low half of first input
            CopyWitnessCell::create(xor_row + 2, 0), // 32 bit high half of first input
            CopyWitnessCell::create(rc_row + 1, 0),  // 64 bit second input
            CopyWitnessCell::create(xor_row + 1, 1), // 32 bit low half of second input
            CopyWitnessCell::create(xor_row + 3, 1), // 32 bit high half of second input
            ZeroWitnessCell::create(),
            ZeroWitnessCell::create(),
            ZeroWitnessCell::create(),
            ZeroWitnessCell::create(),
            ZeroWitnessCell::create(),
            ZeroWitnessCell::create(),
            ZeroWitnessCell::create(),
            ZeroWitnessCell::create(),
            ZeroWitnessCell::create(),
        ],
        [
            CopyWitnessCell::create(rc_row + 2, 0),  // 64 bit output
            CopyWitnessCell::create(xor_row + 1, 0), // 32 bit low half of output
            CopyWitnessCell::create(xor_row + 3, 0), // 32 bit high half of output
            ZeroWitnessCell::create(),
            ZeroWitnessCell::create(),
            ZeroWitnessCell::create(),
            ZeroWitnessCell::create(),
            ZeroWitnessCell::create(),
            ZeroWitnessCell::create(),
            ZeroWitnessCell::create(),
            ZeroWitnessCell::create(),
            ZeroWitnessCell::create(),
            ZeroWitnessCell::create(),
            ZeroWitnessCell::create(),
            ZeroWitnessCell::create(),
        ],
    ];
    for (i, wit) in bit_rows.iter().enumerate() {
        for (col, cell) in wit.iter().enumerate() {
            handle_standard_witness_cell(witness, cell, bit_row + i, col, F::zero())
        }
    }
}

fn init_keccak_xor_rows<F: PrimeField>(
    witness: &mut [Vec<F>; COLUMNS],
    rc_row: usize,
    curr_row: usize,
) {
    let xor_rows = xor_rows(rc_row, curr_row);

    // First, the two first columns of all rows
    for (i, wit) in xor_rows.iter().enumerate() {
        for (col, cell) in wit.iter().enumerate().take(2) {
            handle_standard_witness_cell(witness, cell, curr_row + i, col, F::zero())
        }
    }
    // Next, the rest of the columns of all rows
    for (i, wit) in xor_rows.iter().enumerate() {
        for (col, cell) in wit.iter().enumerate().take(COLUMNS).skip(2) {
            handle_standard_witness_cell(witness, cell, curr_row + i, col, F::zero())
        }
    }
}

/// Extends the xor rows to the full witness
pub fn extend_xor_rows<F: PrimeField>(witness: &mut [Vec<F>; COLUMNS], rc_row: usize) {
    let xor_witness: [Vec<F>; COLUMNS] = array::from_fn(|_| vec![F::zero(); 6]);
    for col in 0..COLUMNS {
        witness[col].extend(xor_witness[col].iter());
    }
    init_keccak_xor_rows(witness, rc_row, rc_row + 5);

    // this needs to be initialized after xor if we copy limbs for xor from range check
    init_keccak_bit_rows(witness, rc_row, rc_row + 5, rc_row + 3);
}

/// Create a keccak xor multiplication witness
/// Input: first input and second input
pub fn create_witness<F: PrimeField>(input1: u64, input2: u64) -> [Vec<F>; COLUMNS] {
    let output = input1 ^ input2;

    // First generic gate with all zeros
    let mut witness: [Vec<F>; COLUMNS] = array::from_fn(|_| vec![F::zero()]);

    extend_single(&mut witness, input1.into());
    extend_single(&mut witness, input2.into());
    extend_single(&mut witness, output.into());
    extend_xor_rows(&mut witness, 1);

    witness
}
