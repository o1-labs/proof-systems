//! Foreign field multiplication witness computation
use crate::{
    circuits::{
        polynomial::COLUMNS,
        polynomials::range_check::witness::range_check_0_row,
        witness::{
            self, ConstantCell, CopyBitsCell, CrumbCell, SumCopyBitsCell, VariableCell, Variables,
            WitnessCell,
        },
    },
    variable_map,
};
use ark_ff::PrimeField;
use std::array;

// Witness layout
//   * The values of the crumbs appear with the least significant crumb first
//     but with big endian ordering of the bits inside the 32/64 element.
//   * The first column of the XOR row and the first and second columns of the
//     Zero rows must be instantiated before the rest, otherwise they copy 0.
//
fn layout_xor64<F: PrimeField>(curr_row: usize) -> [[Box<dyn WitnessCell<F>>; COLUMNS]; 5] {
    [
        // XOR row least significant 16 bits
        xor_row(0, curr_row),
        // Zero row next 16 bits
        xor_row(1, curr_row + 1),
        // XOR row next 16 bits
        xor_row(2, curr_row + 2),
        // XOR row most significant 16 bits
        xor_row(3, curr_row + 3),
        // Zero row low
        zero_row(),
    ]
}

fn layout_rot64<F: PrimeField>(sum: F, curr_row: usize) -> [[Box<dyn WitnessCell<F>>; COLUMNS]; 2] {
    [
        rot_row(sum, curr_row),
        range_check_0_row("shifted", curr_row + 1),
    ]
}

fn rot_row<F: PrimeField>(sum: F, curr_row: usize) -> [Box<dyn WitnessCell<F>>; COLUMNS] {
    [
        VariableCell::create("word"),
        VariableCell::create("rotated"),
        VariableCell::create("excess"),
        /* 12-bit plookups */
        SumCopyBitsCell::create(curr_row, 2, 52, 64, sum),
        SumCopyBitsCell::create(curr_row, 2, 40, 52, sum),
        SumCopyBitsCell::create(curr_row, 2, 28, 40, sum),
        SumCopyBitsCell::create(curr_row, 2, 16, 28, sum),
        /* 2-bit crumbs */
        SumCopyBitsCell::create(curr_row, 2, 14, 16, sum),
        SumCopyBitsCell::create(curr_row, 2, 12, 14, sum),
        SumCopyBitsCell::create(curr_row, 2, 10, 12, sum),
        SumCopyBitsCell::create(curr_row, 2, 8, 10, sum),
        SumCopyBitsCell::create(curr_row, 2, 6, 8, sum),
        SumCopyBitsCell::create(curr_row, 2, 4, 6, sum),
        SumCopyBitsCell::create(curr_row, 2, 2, 4, sum),
        SumCopyBitsCell::create(curr_row, 2, 0, 2, sum),
    ]
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

fn init_rot64<F: PrimeField>(
    witness: &mut [Vec<F>; COLUMNS],
    curr_row: usize,
    word: F,
    rotated: F,
    excess: F,
    shifted: F,
    bound: F,
) {
    let rot_rows = layout_rot64(bound, curr_row);
    witness::init(
        witness,
        curr_row,
        &rot_rows,
        &variable_map!["word" => word, "rotated" => rotated, "excess" => excess, "shifted" => shifted],
    );
}

/// Extends the rot rows to the full witness
pub fn extend_rot_rows<F: PrimeField>(
    witness: &mut [Vec<F>; COLUMNS],
    word: F,
    rotated: F,
    excess: F,
    shifted: F,
    bound: F,
) {
    let rot_row = witness[0].len();
    let rot_witness: [Vec<F>; COLUMNS] = array::from_fn(|_| vec![F::zero(); 2]);
    for col in 0..COLUMNS {
        witness[col].extend(rot_witness[col].iter());
    }
    init_rot64(witness, rot_row, word, rotated, excess, shifted, bound);
}

/// Create a Keccak xor
/// Input: first input and second input
pub fn create_rot<F: PrimeField>(word: u64, rot: u32) -> [Vec<F>; COLUMNS] {
    assert_ne!(rot, 0, "rot must be non-zero");
    let shifted = (word as u128 * 2u128.pow(rot) % 2u128.pow(64)) as u64;
    let excess = word / 2u64.pow(64 - rot);
    let rotated = shifted + excess;
    // Value for the added value for the bound
    let bound = 2u128.pow(64) - 2u128.pow(rot);

    // First generic gate with all zeros to constrain that the two most significant limbs of shifted output are zeros
    let mut witness: [Vec<F>; COLUMNS] = array::from_fn(|_| vec![F::zero()]);
    extend_rot_rows(
        &mut witness,
        F::from(word),
        F::from(rotated),
        F::from(excess),
        F::from(shifted),
        F::from(bound),
    );

    witness
}

fn init_xor64<F: PrimeField>(witness: &mut [Vec<F>; COLUMNS], curr_row: usize, words: (F, F, F)) {
    let xor_rows = layout_xor64(curr_row);

    witness::init(
        witness,
        curr_row,
        &xor_rows,
        &variable_map!["in1" => words.0, "in2" => words.1, "out" => words.2],
    )
}

/// Extends the xor rows to the full witness
pub fn extend_xor_rows<F: PrimeField>(witness: &mut [Vec<F>; COLUMNS], words: (F, F, F)) {
    let xor_row = witness[0].len();
    let xor_witness: [Vec<F>; COLUMNS] = array::from_fn(|_| vec![F::zero(); 5]);
    for col in 0..COLUMNS {
        witness[col].extend(xor_witness[col].iter());
    }
    init_xor64(witness, xor_row, words);
}

/// Create a Keccak xor
/// Input: first input and second input
pub fn create_xor<F: PrimeField>(input1: u64, input2: u64) -> [Vec<F>; COLUMNS] {
    let output = input1 ^ input2;

    // First generic gate with all zeros to constrain final output to be zeros
    let mut witness: [Vec<F>; COLUMNS] = array::from_fn(|_| vec![F::zero()]);

    extend_xor_rows(
        &mut witness,
        (F::from(input1), F::from(input2), F::from(output)),
    );

    witness
}
pub fn view<F: PrimeField>(witness: &[Vec<F>; COLUMNS]) {
    for row in 0..witness[0].len() {
        for col in 0..COLUMNS {
            println!(
                "{} {}: {:?}",
                row,
                col,
                o1_utils::FieldHelpers::to_hex(&witness[col][row])
            );
        }
    }
}
