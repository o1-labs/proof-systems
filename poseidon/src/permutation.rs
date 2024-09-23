//! The permutation module contains the function implementing the permutation used in Poseidon

use crate::constants::SpongeConstants;
use crate::poseidon::{sbox, ArithmeticSpongeParams};
use ark_ff::Field;

fn apply_mds_matrix<F: Field, SC: SpongeConstants>(
    params: &ArithmeticSpongeParams<F>,
    state: &[F],
) -> Vec<F> {
    if SC::PERM_FULL_MDS {
        params
            .mds
            .iter()
            .map(|m| {
                state
                    .iter()
                    .zip(m.iter())
                    .fold(F::zero(), |x, (s, &m)| m * s + x)
            })
            .collect()
    } else {
        vec![
            state[0] + state[2],
            state[0] + state[1],
            state[1] + state[2],
        ]
    }
}

pub fn full_round<F: Field, SC: SpongeConstants>(
    params: &ArithmeticSpongeParams<F>,
    state: &mut Vec<F>,
    r: usize,
) {
    if SC::PERM_FULL_MDS && state.len() == 3 {
        let mut el0 = state[0];
        let mut el1 = state[1];
        let mut el2 = state[2];
        el0 = sbox::<F, SC>(el0);
        el1 = sbox::<F, SC>(el1);
        el2 = sbox::<F, SC>(el2);
        // Manually unrolled loops for multiplying each row by the vector
        state[0] = params.mds[0][0] * el0
            + params.mds[0][1] * el1
            + params.mds[0][2] * el2
            + params.round_constants[r][0];
        state[1] = params.mds[1][0] * el0
            + params.mds[1][1] * el1
            + params.mds[1][2] * el2
            + params.round_constants[r][1];
        state[2] = params.mds[2][0] * el0
            + params.mds[2][1] * el1
            + params.mds[2][2] * el2
            + params.round_constants[r][2];
    } else {
        for state_i in state.iter_mut() {
            *state_i = sbox::<F, SC>(*state_i);
        }
        *state = apply_mds_matrix::<F, SC>(params, state);
        for (i, x) in params.round_constants[r].iter().enumerate() {
            state[i].add_assign(x);
        }
    }
}

pub fn half_rounds<F: Field, SC: SpongeConstants>(
    params: &ArithmeticSpongeParams<F>,
    state: &mut [F],
) {
    for r in 0..SC::PERM_HALF_ROUNDS_FULL {
        for (i, x) in params.round_constants[r].iter().enumerate() {
            state[i].add_assign(x);
        }
        for state_i in state.iter_mut() {
            *state_i = sbox::<F, SC>(*state_i);
        }
        apply_mds_matrix::<F, SC>(params, state);
    }

    for r in 0..SC::PERM_ROUNDS_PARTIAL {
        for (i, x) in params.round_constants[SC::PERM_HALF_ROUNDS_FULL + r]
            .iter()
            .enumerate()
        {
            state[i].add_assign(x);
        }
        state[0] = sbox::<F, SC>(state[0]);
        apply_mds_matrix::<F, SC>(params, state);
    }

    for r in 0..SC::PERM_HALF_ROUNDS_FULL {
        for (i, x) in params.round_constants
            [SC::PERM_HALF_ROUNDS_FULL + SC::PERM_ROUNDS_PARTIAL + r]
            .iter()
            .enumerate()
        {
            state[i].add_assign(x);
        }
        for state_i in state.iter_mut() {
            *state_i = sbox::<F, SC>(*state_i);
        }
        apply_mds_matrix::<F, SC>(params, state);
    }
}

pub fn poseidon_block_cipher<F: Field, SC: SpongeConstants>(
    params: &ArithmeticSpongeParams<F>,
    state: &mut Vec<F>,
) {
    if SC::PERM_HALF_ROUNDS_FULL == 0 {
        if SC::PERM_INITIAL_ARK {
            for (i, x) in params.round_constants[0].iter().enumerate() {
                state[i].add_assign(x);
            }
            for r in 0..SC::PERM_ROUNDS_FULL {
                full_round::<F, SC>(params, state, r + 1);
            }
        } else {
            for r in 0..SC::PERM_ROUNDS_FULL {
                full_round::<F, SC>(params, state, r);
            }
        }
    } else {
        half_rounds::<F, SC>(params, state);
    }
}
