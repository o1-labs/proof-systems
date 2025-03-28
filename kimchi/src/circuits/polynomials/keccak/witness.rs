//! Keccak witness computation

use crate::{
    auto_clone,
    circuits::{
        polynomials::keccak::{
            constants::{
                CAPACITY_IN_BYTES, DIM, KECCAK_COLS, QUARTERS, RATE_IN_BYTES, ROUNDS, STATE_LEN,
            },
            Keccak, OFF,
        },
        witness::{self, IndexCell, Variables, WitnessCell},
    },
    grid, variable_map,
};
use ark_ff::PrimeField;
use core::array;
use num_bigint::BigUint;

pub(crate) const SPARSE_RC: [[u64; QUARTERS]; ROUNDS] = [
    [
        0x0000000000000001,
        0x0000000000000000,
        0x0000000000000000,
        0x0000000000000000,
    ],
    [
        0x1000000010000010,
        0x0000000000000000,
        0x0000000000000000,
        0x0000000000000000,
    ],
    [
        0x1000000010001010,
        0x0000000000000000,
        0x0000000000000000,
        0x1000000000000000,
    ],
    [
        0x1000000000000000,
        0x1000000000000000,
        0x0000000000000000,
        0x1000000000000000,
    ],
    [
        0x1000000010001011,
        0x0000000000000000,
        0x0000000000000000,
        0x0000000000000000,
    ],
    [
        0x0000000000000001,
        0x1000000000000000,
        0x0000000000000000,
        0x0000000000000000,
    ],
    [
        0x1000000010000001,
        0x1000000000000000,
        0x0000000000000000,
        0x1000000000000000,
    ],
    [
        0x1000000000001001,
        0x0000000000000000,
        0x0000000000000000,
        0x1000000000000000,
    ],
    [
        0x0000000010001010,
        0x0000000000000000,
        0x0000000000000000,
        0x0000000000000000,
    ],
    [
        0x0000000010001000,
        0x0000000000000000,
        0x0000000000000000,
        0x0000000000000000,
    ],
    [
        0x1000000000001001,
        0x1000000000000000,
        0x0000000000000000,
        0x0000000000000000,
    ],
    [
        0x0000000000001010,
        0x1000000000000000,
        0x0000000000000000,
        0x0000000000000000,
    ],
    [
        0x1000000010001011,
        0x1000000000000000,
        0x0000000000000000,
        0x0000000000000000,
    ],
    [
        0x0000000010001011,
        0x0000000000000000,
        0x0000000000000000,
        0x1000000000000000,
    ],
    [
        0x1000000010001001,
        0x0000000000000000,
        0x0000000000000000,
        0x1000000000000000,
    ],
    [
        0x1000000000000011,
        0x0000000000000000,
        0x0000000000000000,
        0x1000000000000000,
    ],
    [
        0x1000000000000010,
        0x0000000000000000,
        0x0000000000000000,
        0x1000000000000000,
    ],
    [
        0x0000000010000000,
        0x0000000000000000,
        0x0000000000000000,
        0x1000000000000000,
    ],
    [
        0x1000000000001010,
        0x0000000000000000,
        0x0000000000000000,
        0x0000000000000000,
    ],
    [
        0x0000000000001010,
        0x1000000000000000,
        0x0000000000000000,
        0x1000000000000000,
    ],
    [
        0x1000000010000001,
        0x1000000000000000,
        0x0000000000000000,
        0x1000000000000000,
    ],
    [
        0x1000000010000000,
        0x0000000000000000,
        0x0000000000000000,
        0x1000000000000000,
    ],
    [
        0x0000000000000001,
        0x1000000000000000,
        0x0000000000000000,
        0x0000000000000000,
    ],
    [
        0x1000000000001000,
        0x1000000000000000,
        0x0000000000000000,
        0x1000000000000000,
    ],
];

type Layout<F, const COLUMNS: usize> = Vec<Box<dyn WitnessCell<F, Vec<F>, COLUMNS>>>;

fn layout_round<F: PrimeField>() -> [Layout<F, KECCAK_COLS>; 1] {
    [vec![
        IndexCell::create("state_a", 0, 100),
        IndexCell::create("shifts_c", 100, 180),
        IndexCell::create("dense_c", 180, 200),
        IndexCell::create("quotient_c", 200, 205),
        IndexCell::create("remainder_c", 205, 225),
        IndexCell::create("dense_rot_c", 225, 245),
        IndexCell::create("expand_rot_c", 245, 265),
        IndexCell::create("shifts_e", 265, 665),
        IndexCell::create("dense_e", 665, 765),
        IndexCell::create("quotient_e", 765, 865),
        IndexCell::create("remainder_e", 865, 965),
        IndexCell::create("dense_rot_e", 965, 1065),
        IndexCell::create("expand_rot_e", 1065, 1165),
        IndexCell::create("shifts_b", 1165, 1565),
        IndexCell::create("shifts_sum", 1565, 1965),
    ]]
}

fn layout_sponge<F: PrimeField>() -> [Layout<F, KECCAK_COLS>; 1] {
    [vec![
        IndexCell::create("old_state", 0, 100),
        IndexCell::create("new_state", 100, 200),
        IndexCell::create("bytes", 200, 400),
        IndexCell::create("shifts", 400, 800),
    ]]
}

// Transforms a vector of u64 into a vector of field elements
fn field<F: PrimeField>(input: &[u64]) -> Vec<F> {
    input.iter().map(|x| F::from(*x)).collect::<Vec<F>>()
}

// Contains the quotient, remainder, bound, dense rotated as quarters of at most 16 bits each
// Contains the expansion of the rotated word
pub struct Rotation {
    quotient: Vec<u64>,
    remainder: Vec<u64>,
    dense_rot: Vec<u64>,
    expand_rot: Vec<u64>,
}

impl Rotation {
    // On input the dense quarters of a word, rotate the word offset bits to the left
    fn new(dense: &[u64], offset: u32) -> Self {
        let word = Keccak::compose(dense);
        let rem = word as u128 * 2u128.pow(offset) % 2u128.pow(64);
        let quo = (word as u128) / 2u128.pow(64 - offset);
        let rot = rem + quo;
        assert!(rot as u64 == word.rotate_left(offset));

        Self {
            quotient: Keccak::decompose(quo as u64),
            remainder: Keccak::decompose(rem as u64),
            dense_rot: Keccak::decompose(rot as u64),
            expand_rot: Keccak::decompose(rot as u64)
                .iter()
                .map(|x| Keccak::expand(*x))
                .collect(),
        }
    }

    // On input the dense quarters of many words, rotate the word offset bits to the left
    fn many(words: &[u64], offsets: &[u32]) -> Self {
        assert!(words.len() == QUARTERS * offsets.len());
        let mut quotient = vec![];
        let mut remainder = vec![];
        let mut dense_rot = vec![];
        let mut expand_rot = vec![];
        for (word, offset) in words.chunks(QUARTERS).zip(offsets.iter()) {
            let mut rot = Self::new(word, *offset);
            quotient.append(&mut rot.quotient);
            remainder.append(&mut rot.remainder);
            dense_rot.append(&mut rot.dense_rot);
            expand_rot.append(&mut rot.expand_rot);
        }
        Self {
            quotient,
            remainder,
            dense_rot,
            expand_rot,
        }
    }
}

/// Values involved in Theta permutation step
pub struct Theta {
    shifts_c: Vec<u64>,
    dense_c: Vec<u64>,
    quotient_c: Vec<u64>,
    remainder_c: Vec<u64>,
    dense_rot_c: Vec<u64>,
    expand_rot_c: Vec<u64>,
    state_e: Vec<u64>,
}

impl Theta {
    pub fn create(state_a: &[u64]) -> Self {
        let state_c = Self::compute_state_c(state_a);
        let shifts_c = Keccak::shift(&state_c);
        let dense_c = Keccak::collapse(&Keccak::reset(&shifts_c));
        let rotation_c = Rotation::many(&dense_c, &[1; DIM]);
        let state_d = Self::compute_state_d(&shifts_c, &rotation_c.expand_rot);
        let state_e = Self::compute_state_e(state_a, &state_d);
        let quotient_c = vec![
            rotation_c.quotient[0],
            rotation_c.quotient[4],
            rotation_c.quotient[8],
            rotation_c.quotient[12],
            rotation_c.quotient[16],
        ];
        Self {
            shifts_c,
            dense_c,
            quotient_c,
            remainder_c: rotation_c.remainder,
            dense_rot_c: rotation_c.dense_rot,
            expand_rot_c: rotation_c.expand_rot,
            state_e,
        }
    }

    pub fn shifts_c(&self, i: usize, x: usize, q: usize) -> u64 {
        let shifts_c = grid!(80, &self.shifts_c);
        shifts_c(i, x, q)
    }

    pub fn dense_c(&self, x: usize, q: usize) -> u64 {
        let dense_c = grid!(20, &self.dense_c);
        dense_c(x, q)
    }

    pub fn quotient_c(&self, x: usize) -> u64 {
        self.quotient_c[x]
    }

    pub fn remainder_c(&self, x: usize, q: usize) -> u64 {
        let remainder_c = grid!(20, &self.remainder_c);
        remainder_c(x, q)
    }

    pub fn dense_rot_c(&self, x: usize, q: usize) -> u64 {
        let dense_rot_c = grid!(20, &self.dense_rot_c);
        dense_rot_c(x, q)
    }

    pub fn expand_rot_c(&self, x: usize, q: usize) -> u64 {
        let expand_rot_c = grid!(20, &self.expand_rot_c);
        expand_rot_c(x, q)
    }

    pub fn state_e(&self) -> Vec<u64> {
        self.state_e.clone()
    }

    fn compute_state_c(state_a: &[u64]) -> Vec<u64> {
        let state_a = grid!(100, state_a);
        let mut state_c = vec![];
        for x in 0..DIM {
            for q in 0..QUARTERS {
                state_c.push(
                    state_a(0, x, q)
                        + state_a(1, x, q)
                        + state_a(2, x, q)
                        + state_a(3, x, q)
                        + state_a(4, x, q),
                );
            }
        }
        state_c
    }

    fn compute_state_d(shifts_c: &[u64], expand_rot_c: &[u64]) -> Vec<u64> {
        let shifts_c = grid!(20, shifts_c);
        let expand_rot_c = grid!(20, expand_rot_c);
        let mut state_d = vec![];
        for x in 0..DIM {
            for q in 0..QUARTERS {
                state_d.push(shifts_c((x + DIM - 1) % DIM, q) + expand_rot_c((x + 1) % DIM, q));
            }
        }
        state_d
    }

    fn compute_state_e(state_a: &[u64], state_d: &[u64]) -> Vec<u64> {
        let state_a = grid!(100, state_a);
        let state_d = grid!(20, state_d);
        let mut state_e = vec![];
        for y in 0..DIM {
            for x in 0..DIM {
                for q in 0..QUARTERS {
                    state_e.push(state_a(y, x, q) + state_d(x, q));
                }
            }
        }
        state_e
    }
}

/// Values involved in PiRho permutation step
pub struct PiRho {
    shifts_e: Vec<u64>,
    dense_e: Vec<u64>,
    quotient_e: Vec<u64>,
    remainder_e: Vec<u64>,
    dense_rot_e: Vec<u64>,
    expand_rot_e: Vec<u64>,
    state_b: Vec<u64>,
}

impl PiRho {
    pub fn create(state_e: &[u64]) -> Self {
        let shifts_e = Keccak::shift(state_e);
        let dense_e = Keccak::collapse(&Keccak::reset(&shifts_e));
        let rotation_e = Rotation::many(
            &dense_e,
            &OFF.iter()
                .flatten()
                .map(|x| *x as u32)
                .collect::<Vec<u32>>(),
        );

        let mut state_b = vec![vec![vec![0; QUARTERS]; DIM]; DIM];
        let aux = grid!(100, rotation_e.expand_rot);
        for y in 0..DIM {
            for x in 0..DIM {
                for q in 0..QUARTERS {
                    state_b[(2 * x + 3 * y) % DIM][y][q] = aux(y, x, q);
                }
            }
        }
        let state_b = state_b.iter().flatten().flatten().copied().collect();

        Self {
            shifts_e,
            dense_e,
            quotient_e: rotation_e.quotient,
            remainder_e: rotation_e.remainder,
            dense_rot_e: rotation_e.dense_rot,
            expand_rot_e: rotation_e.expand_rot,
            state_b,
        }
    }

    pub fn shifts_e(&self, i: usize, y: usize, x: usize, q: usize) -> u64 {
        let shifts_e = grid!(400, &self.shifts_e);
        shifts_e(i, y, x, q)
    }

    pub fn dense_e(&self, y: usize, x: usize, q: usize) -> u64 {
        let dense_e = grid!(100, &self.dense_e);
        dense_e(y, x, q)
    }

    pub fn quotient_e(&self, y: usize, x: usize, q: usize) -> u64 {
        let quotient_e = grid!(100, &self.quotient_e);
        quotient_e(y, x, q)
    }

    pub fn remainder_e(&self, y: usize, x: usize, q: usize) -> u64 {
        let remainder_e = grid!(100, &self.remainder_e);
        remainder_e(y, x, q)
    }

    pub fn dense_rot_e(&self, y: usize, x: usize, q: usize) -> u64 {
        let dense_rot_e = grid!(100, &self.dense_rot_e);
        dense_rot_e(y, x, q)
    }

    pub fn expand_rot_e(&self, y: usize, x: usize, q: usize) -> u64 {
        let expand_rot_e = grid!(100, &self.expand_rot_e);
        expand_rot_e(y, x, q)
    }

    pub fn state_b(&self) -> Vec<u64> {
        self.state_b.clone()
    }
}

/// Values involved in Chi permutation step
pub struct Chi {
    shifts_b: Vec<u64>,
    shifts_sum: Vec<u64>,
    state_f: Vec<u64>,
}

impl Chi {
    pub fn create(state_b: &[u64]) -> Self {
        let shifts_b = Keccak::shift(state_b);
        let shiftsb = grid!(400, shifts_b);
        let mut sum = vec![];
        for y in 0..DIM {
            for x in 0..DIM {
                for q in 0..QUARTERS {
                    let not = 0x1111111111111111u64 - shiftsb(0, y, (x + 1) % DIM, q);
                    sum.push(not + shiftsb(0, y, (x + 2) % DIM, q));
                }
            }
        }
        let shifts_sum = Keccak::shift(&sum);
        let shiftsum = grid!(400, shifts_sum);
        let mut state_f = vec![];
        for y in 0..DIM {
            for x in 0..DIM {
                for q in 0..QUARTERS {
                    let and = shiftsum(1, y, x, q);
                    state_f.push(shiftsb(0, y, x, q) + and);
                }
            }
        }

        Self {
            shifts_b,
            shifts_sum,
            state_f,
        }
    }

    pub fn shifts_b(&self, i: usize, y: usize, x: usize, q: usize) -> u64 {
        let shifts_b = grid!(400, &self.shifts_b);
        shifts_b(i, y, x, q)
    }

    pub fn shifts_sum(&self, i: usize, y: usize, x: usize, q: usize) -> u64 {
        let shifts_sum = grid!(400, &self.shifts_sum);
        shifts_sum(i, y, x, q)
    }

    pub fn state_f(&self) -> Vec<u64> {
        self.state_f.clone()
    }
}

/// Values involved in Iota permutation step
pub struct Iota {
    state_g: Vec<u64>,
    round_constants: [u64; QUARTERS],
}

impl Iota {
    pub fn create(state_f: &[u64], round: usize) -> Self {
        let round_constants = SPARSE_RC[round];
        let mut state_g = state_f.to_vec();
        for (i, c) in round_constants.iter().enumerate() {
            state_g[i] = state_f[i] + *c;
        }
        Self {
            state_g,
            round_constants,
        }
    }

    pub fn state_g(&self) -> Vec<u64> {
        self.state_g.clone()
    }

    pub fn round_constants(&self, i: usize) -> u64 {
        self.round_constants[i]
    }
}

/// Creates a witness for the Keccak hash function
/// Input:
/// - message: the message to be hashed
///
/// Note:
///   Requires at least one more row after the keccak gadget so that
///   constraints can access the next row in the squeeze
pub fn extend_keccak_witness<F: PrimeField>(witness: &mut [Vec<F>; KECCAK_COLS], message: BigUint) {
    let padded = Keccak::pad(&message.to_bytes_be());
    let chunks = padded.chunks(RATE_IN_BYTES);

    // The number of rows that need to be added to the witness correspond to
    // - Absorb phase:
    //      - 1 per block for the sponge row
    //      - 24 for the rounds
    // - Squeeze phase:
    //      - 1 for the final sponge row
    let rows: usize = chunks.len() * (ROUNDS + 1) + 1;

    let mut keccak_witness = array::from_fn(|_| vec![F::zero(); rows]);

    // Absorb phase
    let mut row = 0;
    let mut state = vec![0; QUARTERS * DIM * DIM];
    for chunk in chunks {
        let mut block = chunk.to_vec();
        // Pad the block until reaching 200 bytes
        block.append(&mut vec![0; CAPACITY_IN_BYTES]);
        let new_state = Keccak::expand_state(&block);
        auto_clone!(new_state);
        let shifts = Keccak::shift(&new_state());
        let bytes = block.iter().map(|b| *b as u64).collect::<Vec<u64>>();

        // Initialize the absorb sponge row
        witness::init(
            &mut keccak_witness,
            row,
            &layout_sponge(),
            &variable_map!["old_state" => field(&state), "new_state" => field(&new_state()), "bytes" => field(&bytes), "shifts" => field(&shifts)],
        );
        row += 1;

        let xor_state = state
            .iter()
            .zip(new_state())
            .map(|(x, y)| x + y)
            .collect::<Vec<u64>>();

        let mut ini_state = xor_state.clone();

        for round in 0..ROUNDS {
            // Theta
            let theta = Theta::create(&ini_state);

            // PiRho
            let pirho = PiRho::create(&theta.state_e);

            // Chi
            let chi = Chi::create(&pirho.state_b);

            // Iota
            let iota = Iota::create(&chi.state_f, round);

            // Initialize the round row
            witness::init(
                &mut keccak_witness,
                row,
                &layout_round(),
                &variable_map![
                "state_a" => field(&ini_state),
                "shifts_c" => field(&theta.shifts_c),
                "dense_c" => field(&theta.dense_c),
                "quotient_c" => field(&theta.quotient_c),
                "remainder_c" => field(&theta.remainder_c),
                "dense_rot_c" => field(&theta.dense_rot_c),
                "expand_rot_c" => field(&theta.expand_rot_c),
                "shifts_e" => field(&pirho.shifts_e),
                "dense_e" => field(&pirho.dense_e),
                "quotient_e" => field(&pirho.quotient_e),
                "remainder_e" => field(&pirho.remainder_e),
                "dense_rot_e" => field(&pirho.dense_rot_e),
                "expand_rot_e" => field(&pirho.expand_rot_e),
                "shifts_b" => field(&chi.shifts_b),
                "shifts_sum" => field(&chi.shifts_sum)
                ],
            );
            row += 1;
            ini_state = iota.state_g;
        }
        // update state after rounds
        state = ini_state;
    }

    // Squeeze phase

    let new_state = vec![0; STATE_LEN];
    let shifts = Keccak::shift(&state);
    let dense = Keccak::collapse(&Keccak::reset(&shifts));
    let bytes = Keccak::bytestring(&dense);

    // Initialize the squeeze sponge row
    witness::init(
        &mut keccak_witness,
        row,
        &layout_sponge(),
        &variable_map!["old_state" => field(&state), "new_state" => field(&new_state), "bytes" => field(&bytes), "shifts" => field(&shifts)],
    );

    for col in 0..KECCAK_COLS {
        witness[col].extend(keccak_witness[col].iter());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuits::polynomials::keccak::RC;

    #[test]
    fn test_sparse_round_constants() {
        for round in 0..ROUNDS {
            let round_constants = Keccak::sparse(RC[round]);
            for (i, rc) in round_constants.iter().enumerate().take(QUARTERS) {
                assert_eq!(*rc, SPARSE_RC[round][i]);
            }
        }
    }
}
