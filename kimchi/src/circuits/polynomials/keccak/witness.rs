//! Foreign field multiplication witness computation
use crate::{
    circuits::{
        polynomial::COLUMNS,
        polynomials::range_check::witness::range_check_0_row,
        witness::{self, SumCopyBitsCell, VariableCell, Variables, WitnessCell},
    },
    variable_map,
};
use ark_ff::PrimeField;
use std::array;

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
