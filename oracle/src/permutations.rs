
use ark_ff::Field;
use crate::poseidon::{sbox,ArithmeticSpongeParams,SpongeConstants};

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
    for state_i in state.iter_mut() {
        *state_i = sbox::<F, SC>(*state_i);
    }
    *state = apply_mds_matrix::<F, SC>(params, state);
    for (i, x) in params.round_constants[r].iter().enumerate() {
        state[i].add_assign(x);
    }
}

fn half_rounds<F: Field, SC: SpongeConstants>(
    params: &ArithmeticSpongeParams<F>,
    state: &mut Vec<F>,
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