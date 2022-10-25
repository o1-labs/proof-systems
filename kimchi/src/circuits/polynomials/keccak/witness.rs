//! Foreign field multiplication witness computation
use crate::{
    circuits::{
        polynomial::COLUMNS,
        polynomials::range_check::witness::extend_single,
        witness::{self, ConstantCell, CopyBitsCell, CopyCell, Variables, WitnessCell},
    },
    variables,
};
use ark_ff::PrimeField;
use std::array;

/// Identifier of halves in decomposition
#[derive(Copy, Clone)]
enum Half {
    Lo = 0,
    Hi = 1,
}

fn xor_row<F: PrimeField>(
    word_row: usize,
    curr_row: usize,
    half: Half,
) -> [Box<dyn WitnessCell<F>>; COLUMNS] {
    [
        CopyCell::create(word_row, 1 + half as usize), // in1
        ConstantCell::create(F::zero()),
        ConstantCell::create(F::zero()),
        CopyBitsCell::create(curr_row + 1, 1, 0, 4), // in2_0
        CopyBitsCell::create(curr_row + 1, 1, 4, 8), // in2_1
        CopyBitsCell::create(curr_row + 1, 1, 8, 12), // in2_2
        CopyBitsCell::create(curr_row + 1, 1, 12, 16), // in2_3
        CopyBitsCell::create(curr_row, 0, 0, 4),     // in1_0
        CopyBitsCell::create(curr_row, 0, 4, 8),     // in1_1
        CopyBitsCell::create(curr_row, 0, 8, 12),    // in1_2
        CopyBitsCell::create(curr_row, 0, 12, 16),   // in1_3
        CopyBitsCell::create(curr_row + 1, 0, 0, 4), // out_0
        CopyBitsCell::create(curr_row + 1, 0, 4, 8), // out_1
        CopyBitsCell::create(curr_row + 1, 0, 8, 12), // out_2
        CopyBitsCell::create(curr_row + 1, 0, 12, 16), // out_3
    ]
}

fn zero_row<F: PrimeField>(
    word_row: usize,
    curr_row: usize,
    half: Half,
) -> [Box<dyn WitnessCell<F>>; COLUMNS] {
    [
        CopyCell::create(word_row + 1, 1 + half as usize), // out
        CopyCell::create(word_row, 4 + half as usize),     // in2
        ConstantCell::create(F::zero()),
        CopyBitsCell::create(curr_row + 1, 1, 16, 20), // in2_8
        CopyBitsCell::create(curr_row + 1, 1, 20, 24), // in2_9
        CopyBitsCell::create(curr_row + 1, 1, 24, 28), // in2_10
        CopyBitsCell::create(curr_row + 1, 1, 28, 32), // in2_11
        CopyBitsCell::create(curr_row, 0, 16, 20),     // in1_8
        CopyBitsCell::create(curr_row, 0, 20, 24),     // in1_9
        CopyBitsCell::create(curr_row, 0, 24, 28),     // in1_10
        CopyBitsCell::create(curr_row, 0, 28, 32),     // in1_11
        CopyBitsCell::create(curr_row + 1, 0, 16, 20), // out_8
        CopyBitsCell::create(curr_row + 1, 0, 20, 24), // out_9
        CopyBitsCell::create(curr_row + 1, 0, 24, 28), // out_10
        CopyBitsCell::create(curr_row + 1, 0, 28, 32), // out_11
    ]
}

fn word_rows<F: PrimeField>(rc_row: usize) -> [[Box<dyn WitnessCell<F>>; COLUMNS]; 2] {
    [
        [
            CopyCell::create(rc_row, 0),                 // 64 bit first input
            CopyBitsCell::create(rc_row, 0, 0, 32),      // 32 bit low half of first input
            CopyBitsCell::create(rc_row, 0, 32, 64),     // 32 bit high half of first input
            CopyCell::create(rc_row + 1, 0),             // 64 bit second input
            CopyBitsCell::create(rc_row + 1, 0, 0, 32),  // 32 bit low half of second input
            CopyBitsCell::create(rc_row + 1, 0, 32, 64), // 32 bit high half of second input
            ConstantCell::create(F::zero()),
            ConstantCell::create(F::zero()),
            ConstantCell::create(F::zero()),
            ConstantCell::create(F::zero()),
            ConstantCell::create(F::zero()),
            ConstantCell::create(F::zero()),
            ConstantCell::create(F::zero()),
            ConstantCell::create(F::zero()),
            ConstantCell::create(F::zero()),
        ],
        [
            CopyCell::create(rc_row + 2, 0),             // 64 bit output
            CopyBitsCell::create(rc_row + 2, 0, 0, 32),  // 32 bit low half of output
            CopyBitsCell::create(rc_row + 2, 0, 32, 64), // 32 bit high half of output
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
        ],
    ]
}

// Witness layout
//   * The values of the crumbs appear with the least significant crumb first
//     but with big endian ordering of the bits inside the 32/64 element.
//   * The first column of the XOR row and the first and second columns of the
//     Zero rows must be instantiated before the rest, otherwise they copy 0.
//
fn layout_xor<F: PrimeField>(
    word_row: usize,
    curr_row: usize,
) -> [[Box<dyn WitnessCell<F>>; COLUMNS]; 4] {
    // TODO: new more automated pattern for the 4-bit crumbs
    [
        // XOR row low
        xor_row(word_row, curr_row, Half::Lo),
        // Zero row low
        zero_row(word_row, curr_row, Half::Lo),
        // XOR row low
        xor_row(word_row, curr_row + 2, Half::Hi),
        // Zero row low
        zero_row(word_row, curr_row + 2, Half::Hi),
    ]
}

/// Initializes two rows of inputs pairs and one output value
fn init_keccak_word_rows<F: PrimeField>(
    witness: &mut [Vec<F>; COLUMNS],
    rc_row: usize,
    word_row: usize,
) {
    let word_rows = word_rows(rc_row);
    witness::init(witness, word_row, &word_rows, &variables!());
}

fn init_keccak_xor_rows<F: PrimeField>(
    witness: &mut [Vec<F>; COLUMNS],
    word_row: usize,
    curr_row: usize,
) {
    let xor_rows = layout_xor(word_row, curr_row);

    // First, the two first columns of all rows
    for (i, wit) in xor_rows.iter().enumerate() {
        for (col, _cell) in wit.iter().enumerate().take(2) {
            witness::init_cell(witness, curr_row, i, col, &xor_rows, &variables!());
        }
    }
    // Next, the rest of the columns of all rows
    for (i, wit) in xor_rows.iter().enumerate() {
        for (col, _cell) in wit.iter().enumerate().take(COLUMNS).skip(2) {
            witness::init_cell(witness, curr_row, i, col, &xor_rows, &variables!());
        }
    }
}

/// Extends the xor rows to the full witness
pub fn extend_xor_rows<F: PrimeField>(
    witness: &mut [Vec<F>; COLUMNS],
    word_row: usize,
    xor_row: usize,
) {
    let xor_witness: [Vec<F>; COLUMNS] = array::from_fn(|_| vec![F::zero(); 4]);
    for col in 0..COLUMNS {
        witness[col].extend(xor_witness[col].iter());
    }
    init_keccak_xor_rows(witness, word_row, xor_row);
}

/// Extends the bit decomposition rows to the full witness
pub fn extend_word_rows<F: PrimeField>(
    witness: &mut [Vec<F>; COLUMNS],
    rc_row: usize,
    word_row: usize,
) {
    let bit_witness: [Vec<F>; COLUMNS] = array::from_fn(|_| vec![F::zero(); 2]);
    for col in 0..COLUMNS {
        witness[col].extend(bit_witness[col].iter());
    }
    init_keccak_word_rows(witness, rc_row, word_row);
}

/// Create a keccak xor multiplication witness
/// Input: first input and second input
pub fn create<F: PrimeField>(input1: u64, input2: u64) -> [Vec<F>; COLUMNS] {
    let output = input1 ^ input2;

    // First generic gate with all zeros
    let mut witness: [Vec<F>; COLUMNS] = array::from_fn(|_| vec![F::zero()]);

    let rc_row = 1;
    let word_row = rc_row + 3;
    let xor_row = word_row + 2;
    extend_single(&mut witness, input1.into());
    extend_single(&mut witness, input2.into());
    extend_single(&mut witness, output.into());
    extend_word_rows(&mut witness, rc_row, word_row);
    extend_xor_rows(&mut witness, word_row, xor_row);

    witness
}
