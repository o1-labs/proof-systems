//! Keccak witness computation

use std::array;

use crate::circuits::polynomials::keccak::{compose, decompose, expand_state, quarters, RC};
use crate::{
    auto_clone,
    circuits::{
        polynomials::keccak::ROUNDS,
        witness::{self, IndexCell, Variables, WitnessCell},
    },
    grid, variable_map,
};
use ark_ff::PrimeField;
use num_bigint::BigUint;

use super::{
    bytestring, collapse, expand, pad, reset, shift, sparse, CAPACITY_IN_BYTES, DIM, KECCAK_COLS,
    OFF, QUARTERS, RATE_IN_BYTES,
};

type Layout<F, const COLUMNS: usize> = Vec<Box<dyn WitnessCell<F, Vec<F>, COLUMNS>>>;

fn layout_round<F: PrimeField>() -> [Layout<F, KECCAK_COLS>; 1] {
    [vec![
        IndexCell::create("state_a", 0, 100),
        IndexCell::create("state_c", 100, 120),
        IndexCell::create("shifts_c", 120, 200),
        IndexCell::create("dense_c", 200, 220),
        IndexCell::create("quotient_c", 220, 240),
        IndexCell::create("remainder_c", 240, 260),
        IndexCell::create("bound_c", 260, 280),
        IndexCell::create("dense_rot_c", 280, 300),
        IndexCell::create("expand_rot_c", 300, 320),
        IndexCell::create("state_d", 320, 340),
        IndexCell::create("state_e", 340, 440),
        IndexCell::create("shifts_e", 440, 840),
        IndexCell::create("dense_e", 840, 940),
        IndexCell::create("quotient_e", 940, 1040),
        IndexCell::create("remainder_e", 1040, 1140),
        IndexCell::create("bound_e", 1140, 1240),
        IndexCell::create("dense_rot_e", 1240, 1340),
        IndexCell::create("expand_rot_e", 1340, 1440),
        IndexCell::create("state_b", 1440, 1540),
        IndexCell::create("shifts_b", 1540, 1940),
        IndexCell::create("shifts_sum", 1940, 2340),
        IndexCell::create("f00", 2340, 2344),
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
struct Rotation {
    quotient: Vec<u64>,
    remainder: Vec<u64>,
    bound: Vec<u64>,
    dense_rot: Vec<u64>,
    expand_rot: Vec<u64>,
}

impl Rotation {
    // Returns rotation of 0 bits
    fn none(dense: &[u64]) -> Self {
        Self {
            quotient: vec![0; QUARTERS],
            remainder: dense.to_vec(),
            bound: vec![0xFFFF; QUARTERS],
            dense_rot: dense.to_vec(),
            expand_rot: dense.iter().map(|x| expand(*x)).collect(),
        }
    }

    // On input the dense quarters of a word, rotate the word offset bits to the left
    fn new(dense: &[u64], offset: u32) -> Self {
        if offset == 0 {
            return Self::none(dense);
        }
        let word = compose(dense);
        let rem = (word as u128 * 2u128.pow(offset) % 2u128.pow(64)) as u64;
        let quo = word / 2u64.pow(64 - offset);
        let bnd = (quo as u128) + 2u128.pow(64) - 2u128.pow(offset);
        let rot = rem + quo;
        assert!(rot == word.rotate_left(offset));

        Self {
            quotient: decompose(quo),
            remainder: decompose(rem),
            bound: decompose(bnd as u64),
            dense_rot: decompose(rot),
            expand_rot: decompose(rot).iter().map(|x| expand(*x)).collect(),
        }
    }

    // On input the dense quarters of many words, rotate the word offset bits to the left
    fn many(words: &[u64], offsets: &[u32]) -> Self {
        assert!(words.len() == QUARTERS * offsets.len());
        let mut quotient = vec![];
        let mut remainder = vec![];
        let mut bound = vec![];
        let mut dense_rot = vec![];
        let mut expand_rot = vec![];
        for (word, offset) in words.chunks(QUARTERS).zip(offsets.iter()) {
            let mut rot = Self::new(word, *offset);
            quotient.append(&mut rot.quotient);
            remainder.append(&mut rot.remainder);
            bound.append(&mut rot.bound);
            dense_rot.append(&mut rot.dense_rot);
            expand_rot.append(&mut rot.expand_rot);
        }
        Self {
            quotient,
            remainder,
            bound,
            dense_rot,
            expand_rot,
        }
    }
}

struct Theta {
    state_c: Vec<u64>,
    shifts_c: Vec<u64>,
    dense_c: Vec<u64>,
    quotient_c: Vec<u64>,
    remainder_c: Vec<u64>,
    bound_c: Vec<u64>,
    dense_rot_c: Vec<u64>,
    expand_rot_c: Vec<u64>,
    state_d: Vec<u64>,
    state_e: Vec<u64>,
}

impl Theta {
    fn create(state_a: &[u64]) -> Self {
        let state_c = Self::compute_state_c(state_a);
        let shifts_c = shift(&state_c);
        let dense_c = collapse(&reset(&shifts_c));
        let rotation_c = Rotation::many(&dense_c, &[1; DIM]);
        let state_d = Self::compute_state_d(&shifts_c, &rotation_c.expand_rot);
        let state_e = Self::compute_state_e(state_a, &state_d);
        Self {
            state_c,
            shifts_c,
            dense_c,
            quotient_c: rotation_c.quotient,
            remainder_c: rotation_c.remainder,
            bound_c: rotation_c.bound,
            dense_rot_c: rotation_c.dense_rot,
            expand_rot_c: rotation_c.expand_rot,
            state_d,
            state_e,
        }
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

struct PiRho {
    shifts_e: Vec<u64>,
    dense_e: Vec<u64>,
    quotient_e: Vec<u64>,
    remainder_e: Vec<u64>,
    bound_e: Vec<u64>,
    dense_rot_e: Vec<u64>,
    expand_rot_e: Vec<u64>,
    state_b: Vec<u64>,
}

impl PiRho {
    fn create(state_e: &[u64]) -> Self {
        let shifts_e = shift(state_e);
        let dense_e = collapse(&reset(&shifts_e));
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
            bound_e: rotation_e.bound,
            dense_rot_e: rotation_e.dense_rot,
            expand_rot_e: rotation_e.expand_rot,
            state_b,
        }
    }
}

struct Chi {
    shifts_b: Vec<u64>,
    shifts_sum: Vec<u64>,
    state_f: Vec<u64>,
}

impl Chi {
    fn create(state_b: &[u64]) -> Self {
        let shifts_b = shift(state_b);
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
        let shifts_sum = shift(&sum);
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
}

struct Iota {
    state_g: Vec<u64>,
}

impl Iota {
    fn create(state_f: Vec<u64>, round: usize) -> Self {
        let rc = sparse(RC[round]);
        let mut state_g = state_f.clone();
        for (i, c) in rc.iter().enumerate() {
            state_g[i] = state_f[i] + *c;
        }
        Self { state_g }
    }
}

/// Creates a witness for the Keccak hash function
/// Input:
/// - message: the message to be hashed
/// Note:
/// Requires at least one more row after the keccak gadget so that
/// constraints can access the next row in the squeeze
pub fn extend_keccak_witness<F: PrimeField>(witness: &mut [Vec<F>; KECCAK_COLS], message: BigUint) {
    let padded = pad(&message.to_bytes_be());
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
        let dense = quarters(&block);
        let new_state = expand_state(&block);
        auto_clone!(new_state);
        let shifts = shift(&new_state());
        let bytes = block.iter().map(|b| *b as u64).collect::<Vec<u64>>();

        // Initialize the absorb sponge row
        witness::init(
            &mut keccak_witness,
            row,
            &layout_sponge(),
            &variable_map!["old_state" => field(&state), "new_state" => field(&new_state()), "dense" => field(&dense), "bytes" => field(&bytes), "shifts" => field(&shifts)],
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
            let f00 = chi
                .state_f
                .clone()
                .into_iter()
                .take(QUARTERS)
                .collect::<Vec<u64>>();

            // Iota
            let iota = Iota::create(chi.state_f, round);

            // Initialize the round row
            witness::init(
                &mut keccak_witness,
                row,
                &layout_round(),
                &variable_map![
                "state_a" => field(&ini_state),
                "state_c" => field(&theta.state_c),
                "shifts_c" => field(&theta.shifts_c),
                "dense_c" => field(&theta.dense_c),
                "quotient_c" => field(&theta.quotient_c),
                "remainder_c" => field(&theta.remainder_c),
                "bound_c" => field(&theta.bound_c),
                "dense_rot_c" => field(&theta.dense_rot_c),
                "expand_rot_c" => field(&theta.expand_rot_c),
                "state_d" => field(&theta.state_d),
                "state_e" => field(&theta.state_e),
                "shifts_e" => field(&pirho.shifts_e),
                "dense_e" => field(&pirho.dense_e),
                "quotient_e" => field(&pirho.quotient_e),
                "remainder_e" => field(&pirho.remainder_e),
                "bound_e" => field(&pirho.bound_e),
                "dense_rot_e" => field(&pirho.dense_rot_e),
                "expand_rot_e" => field(&pirho.expand_rot_e),
                "state_b" => field(&pirho.state_b),
                "shifts_b" => field(&chi.shifts_b),
                "shifts_sum" => field(&chi.shifts_sum),
                "f00" => field(&f00)
                ],
            );
            row += 1;
            ini_state = iota.state_g;
        }
        // update state after rounds
        state = ini_state;
    }

    // Squeeze phase

    let new_state = vec![0; QUARTERS * DIM * DIM];
    let shifts = shift(&state);
    let dense = collapse(&reset(&shifts));
    let bytes = bytestring(&dense);

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
