//! Keccak gadget
use std::array;

use ark_ff::PrimeField;

use crate::circuits::{
    gate::{CircuitGate, Connect},
    polynomial::COLUMNS,
    polynomials::{generic::GenericGateSpec, rot::create_witness_rot},
    wires::Wire,
};

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
    /// Creates Keccak gadget.
    /// Right now it only creates an initial generic gate with all zeros starting on `new_row` and then
    /// calls the Keccak rotation gadget
    pub fn create_keccak(new_row: usize) -> (usize, Vec<Self>) {
        // Initial Generic gate to constrain the prefix of the output to be zero
        let mut gates = vec![CircuitGate::<F>::create_generic_gadget(
            Wire::new(new_row),
            GenericGateSpec::Pub,
            None,
        )];
        Self::create_keccak_rot(&mut gates, new_row + 1, new_row)
    }

    /// Creates Keccak rotation gates for the whole table (skipping the rotation by 0)
    pub fn create_keccak_rot(
        gates: &mut Vec<Self>,
        new_row: usize,
        zero_row: usize,
    ) -> (usize, Vec<Self>) {
        let mut rot_row = new_row;
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
        (rot_row, gates.to_vec())
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
            create_witness_rot(&mut witness, state[x][y], rot);
        }
    }
    witness
}
