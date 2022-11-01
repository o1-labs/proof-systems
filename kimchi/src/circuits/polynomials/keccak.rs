//! Keccak gadget
use std::array;

use ark_ff::PrimeField;

use crate::circuits::{
    gate::{CircuitGate, Connect},
    polynomial::COLUMNS,
    polynomials::{generic::GenericGateSpec, rot::extend_rot_rows},
    wires::Wire,
};

impl<F: PrimeField> CircuitGate<F> {
    /// Create the Keccak gadget
    /// TODO: right now it only creates a Generic gate followed by the Xor64 gates
    pub fn create_keccak(new_row: usize) -> (usize, Vec<Self>) {
        Self::create_xor(new_row, 64)
    }
}

/// Creates the 5x5 table of rotation bits for Keccak modulo 64
/// | y \ x |  0 |  1 |  2 |  3 |  4 |
/// | ----- | -- | -- | -- | -- | -- |
/// | 0     |  0 |  1 | 62 | 28 | 27 |
/// | 1     | 36 | 44 |  6 | 55 | 20 |
/// | 2     |  3 | 10 | 43 | 25 | 39 |
/// | 3     | 41 | 45 | 15 | 21 |  8 |
/// | 4     | 18 |  2 | 61 | 56 | 14 |
pub const ROT_TAB: [[u32; 5]; 5] = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
];

impl<F: PrimeField> CircuitGate<F> {
    /// Creates Keccak rotation gates for the whole table (skipping the rotation by 0)
    pub fn create_keccak_rot(new_row: usize) -> (usize, Vec<Self>) {
        // Initial Generic gate to constrain the output to be zero
        let zero_row = new_row;
        let mut gates = vec![CircuitGate::<F>::create_generic_gadget(
            Wire::new(new_row),
            GenericGateSpec::Pub,
            None,
        )];
        let mut rot_row = zero_row + 1;
        for x in 0..5 {
            for y in 0..5 {
                let rot = ROT_TAB[x][y];
                if rot == 0 {
                    continue;
                }
                let mut rot64_gates = Self::create_rot64(rot_row, rot);
                rot_row += rot64_gates.len();
                // Append them to the full gates vector
                gates.append(&mut rot64_gates);
                // Check that 2 most significant limbs of shifted are zero
                gates.connect_64bit(zero_row, rot_row - 1);
            }
        }
        (rot_row, gates)
    }
}

/// Create a Keccak rotation (whole table)
/// Input: state (5x5) array of words to be rotated
pub fn create_witness_keccak_rot<F: PrimeField>(state: [[u64; 5]; 5]) -> [Vec<F>; COLUMNS] {
    // First generic gate with all zeros to constrain that the two most significant limbs of shifted output are zeros
    let mut witness: [Vec<F>; COLUMNS] = array::from_fn(|_| vec![F::zero()]);
    for x in 0..5 {
        for y in 0..5 {
            let rot = ROT_TAB[x][y];
            if rot == 0 {
                continue;
            }
            let word = state[x][y];
            let shifted = (word as u128 * 2u128.pow(rot) % 2u128.pow(64)) as u64;
            let excess = word / 2u64.pow(64 - rot);
            let rotated = shifted + excess;
            // Value for the added value for the bound
            let bound = 2u128.pow(64) - 2u128.pow(rot);
            extend_rot_rows(
                &mut witness,
                F::from(word),
                F::from(rotated),
                F::from(excess),
                F::from(shifted),
                F::from(bound),
            );
        }
    }
    witness
}
