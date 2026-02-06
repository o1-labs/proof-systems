//! The permutation module contains the function implementing the permutation
//! used in Poseidon.

extern crate alloc;

use crate::{
    constants::SpongeConstants,
    poseidon::{sbox, ArithmeticSpongeParams},
};
use ark_ff::Field;
const MDS_WIDTH: usize = 3;

fn apply_mds_matrix<F: Field, SC: SpongeConstants>(
    mds: [[F; MDS_WIDTH]; MDS_WIDTH],
    state: &mut [F],
) {
    // optimization
    if !SC::PERM_FULL_MDS {
        let s0 = state[0];
        let s1 = state[1];
        let s2 = state[2];

        state[0] = s0 + s2;
        state[1] = s0 + s1;
        state[2] = s1 + s2;
        return;
    }

    let mut new_state = [F::zero(); MDS_WIDTH];

    for (new_state, mds) in new_state.iter_mut().zip(mds.iter()) {
        *new_state = mds
            .iter()
            .copied()
            .zip(state.iter())
            .map(|(md, state)| md * state)
            .sum();
    }

    new_state
        .into_iter()
        .zip(state.iter_mut())
        .for_each(|(new_s, s)| {
            *s = new_s;
        });
}

/// Apply a full round of the permutation.
/// A full round is composed of the following steps:
/// - Apply the S-box to each element of the state.
/// - Apply the MDS matrix to the state.
/// - Add the round constants to the state.
///
/// The function has side-effect and the parameter state is modified.
pub(crate) fn full_round<F: Field, SC: SpongeConstants, const FULL_ROUNDS: usize>(
    params: &ArithmeticSpongeParams<F, FULL_ROUNDS>,
    state: &mut [F],
    r: usize,
) {
    for s in &mut *state {
        *s = sbox::<F, SC>(*s);
    }
    let mds = params.mds;

    apply_mds_matrix::<F, SC>(mds, state);

    for (i, x) in params.round_constants[r].iter().enumerate() {
        state[i].add_assign(x);
    }
}

pub fn half_rounds<F: Field, SC: SpongeConstants, const FULL_ROUNDS: usize>(
    params: &ArithmeticSpongeParams<F, FULL_ROUNDS>,
    state: &mut [F],
) {
    for r in 0..SC::PERM_HALF_ROUNDS_FULL {
        for (i, x) in params.round_constants[r].iter().enumerate() {
            state[i].add_assign(x);
        }

        for state_i in state.iter_mut() {
            *state_i = sbox::<F, SC>(*state_i);
        }

        apply_mds_matrix::<F, SC>(params.mds, state);
    }

    for r in 0..SC::PERM_ROUNDS_PARTIAL {
        for (i, x) in params.round_constants[SC::PERM_HALF_ROUNDS_FULL + r]
            .iter()
            .enumerate()
        {
            state[i].add_assign(x);
        }
        state[0] = sbox::<F, SC>(state[0]);

        apply_mds_matrix::<F, SC>(params.mds, state);
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

        apply_mds_matrix::<F, SC>(params.mds, state);
    }
}

/// Run a single instance of the Poseidon permutation.
///
/// # Arguments
///
/// * `params` - The Poseidon parameters containing the MDS matrix and round constants.
/// * `state` - The state array to permute in place. Must have length
///   [`SpongeConstants::SPONGE_WIDTH`] (e.g., `3` for
///   [`PlonkSpongeConstantsKimchi`](crate::constants::PlonkSpongeConstantsKimchi)).
///
/// # Security
///
/// **NOTE:** Because this function can only be called with fixed-length input
/// states of length [`SpongeConstants::SPONGE_WIDTH`], the function will not
/// incur in trailing-zeros padding type of collisions.
///
pub fn poseidon_block_cipher<F: Field, SC: SpongeConstants, const FULL_ROUNDS: usize>(
    params: &ArithmeticSpongeParams<F, FULL_ROUNDS>,
    state: &mut [F],
) {
    if SC::PERM_HALF_ROUNDS_FULL == 0 {
        if SC::PERM_INITIAL_ARK {
            state
                .iter_mut()
                .zip(params.round_constants[0].iter())
                .for_each(|(s, x)| {
                    s.add_assign(x);
                });

            for r in 0..SC::PERM_ROUNDS_FULL {
                full_round::<_, SC, FULL_ROUNDS>(params, state, r + 1);
            }
        } else {
            for r in 0..SC::PERM_ROUNDS_FULL {
                full_round::<_, SC, FULL_ROUNDS>(params, state, r);
            }
        }
    } else {
        half_rounds::<_, SC, FULL_ROUNDS>(params, state);
    }
}
