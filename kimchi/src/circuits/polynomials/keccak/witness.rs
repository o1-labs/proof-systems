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

/// Identifier of halves in decomposition
#[derive(Copy, Clone)]
enum Half {
    Lo = 0,
    Hi = 1,
}

const fn xor_row(bit_row: usize, curr_row: usize, half: Half) -> [WitnessCell; COLUMNS] {
    [
        CopyWitnessCell::create(bit_row, 1 + half as usize), // in1
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

const fn zero_row(bit_row: usize, curr_row: usize, half: Half) -> [WitnessCell; COLUMNS] {
    [
        CopyWitnessCell::create(bit_row + 1, 1 + half as usize), // out
        CopyWitnessCell::create(bit_row, 4 + half as usize),     // in2
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

const fn bit_rows(rc_row: usize) -> [[WitnessCell; COLUMNS]; 2] {
    [
        [
            CopyWitnessCell::create(rc_row, 0),         // 64 bit first input
            LimbWitnessCell::create(rc_row, 0, 0, 32),  // 32 bit low half of first input
            LimbWitnessCell::create(rc_row, 0, 32, 64), // 32 bit high half of first input
            CopyWitnessCell::create(rc_row + 1, 0),     // 64 bit second input
            LimbWitnessCell::create(rc_row + 1, 0, 0, 32), // 32 bit low half of second input
            LimbWitnessCell::create(rc_row + 1, 0, 32, 64), // 32 bit high half of second input
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
            CopyWitnessCell::create(rc_row + 2, 0),        // 64 bit output
            LimbWitnessCell::create(rc_row + 2, 0, 0, 32), // 32 bit low half of output
            LimbWitnessCell::create(rc_row + 2, 0, 32, 64), // 32 bit high half of output
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
    ]
}

// Witness layout
//   * The values of the crumbs appear with the least significant crumb first
//     but with big endian ordering of the bits inside the 32/64 element.
//   * The first column of the XOR row and the first and second columns of the
//     Zero rows must be instantiated before the rest, otherwise they copy 0.
//
const fn xor_rows(bit_row: usize, curr_row: usize) -> [[WitnessCell; COLUMNS]; 4] {
    // TODO: new more automated pattern for the 4-bit crumbs
    [
        // XOR row low
        xor_row(bit_row, curr_row, Half::Lo),
        // Zero row low
        zero_row(bit_row, curr_row, Half::Lo),
        // XOR row low
        xor_row(bit_row, curr_row + 2, Half::Hi),
        // Zero row low
        zero_row(bit_row, curr_row + 2, Half::Hi),
    ]
}

/// Initializes two rows of inputs pairs and one output value
fn init_keccak_bit_rows<F: PrimeField>(
    witness: &mut [Vec<F>; COLUMNS],
    rc_row: usize,
    bit_row: usize,
) {
    let bit_rows = bit_rows(rc_row);
    for (i, wit) in bit_rows.iter().enumerate() {
        for (col, cell) in wit.iter().enumerate() {
            handle_standard_witness_cell(witness, cell, bit_row + i, col, F::zero())
        }
    }
}

fn init_keccak_xor_rows<F: PrimeField>(
    witness: &mut [Vec<F>; COLUMNS],
    bit_row: usize,
    curr_row: usize,
) {
    let xor_rows = xor_rows(bit_row, curr_row);

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
pub fn extend_xor_rows<F: PrimeField>(
    witness: &mut [Vec<F>; COLUMNS],
    bit_row: usize,
    xor_row: usize,
) {
    let xor_witness: [Vec<F>; COLUMNS] = array::from_fn(|_| vec![F::zero(); 4]);
    for col in 0..COLUMNS {
        witness[col].extend(xor_witness[col].iter());
    }
    init_keccak_xor_rows(witness, bit_row, xor_row);
}

/// Extends the bit decomposition rows to the full witness
pub fn extend_bit_rows<F: PrimeField>(
    witness: &mut [Vec<F>; COLUMNS],
    rc_row: usize,
    bit_row: usize,
) {
    let bit_witness: [Vec<F>; COLUMNS] = array::from_fn(|_| vec![F::zero(); 2]);
    for col in 0..COLUMNS {
        witness[col].extend(bit_witness[col].iter());
    }
    init_keccak_bit_rows(witness, rc_row, bit_row);
}

/// Create a keccak xor multiplication witness
/// Input: first input and second input
pub fn create_witness<F: PrimeField>(input1: u64, input2: u64) -> [Vec<F>; COLUMNS] {
    let output = input1 ^ input2;

    // First generic gate with all zeros
    let mut witness: [Vec<F>; COLUMNS] = array::from_fn(|_| vec![F::zero()]);

    let rc_row = 1;
    let bit_row = rc_row + 3;
    let xor_row = bit_row + 2;
    extend_single(&mut witness, input1.into());
    extend_single(&mut witness, input2.into());
    extend_single(&mut witness, output.into());
    extend_bit_rows(&mut witness, rc_row, bit_row);
    extend_xor_rows(&mut witness, bit_row, xor_row);

    witness
}
