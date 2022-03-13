//! This module implements Poseidon Hash Function primitive

use ark_ff::Field;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

pub trait SpongeConstants {
    const SPONGE_CAPACITY: usize = 1;
    const SPONGE_WIDTH: usize = 3;
    const SPONGE_RATE: usize = 2;
    const PERM_ROUNDS_FULL: usize;
    const PERM_ROUNDS_PARTIAL: usize;
    const PERM_HALF_ROUNDS_FULL: usize;
    const PERM_SBOX: u32;
    const PERM_FULL_MDS: bool;
    const PERM_INITIAL_ARK: bool;
}

#[derive(Clone)]
pub struct PlonkSpongeConstantsLegacy {}

impl SpongeConstants for PlonkSpongeConstantsLegacy {
    const SPONGE_CAPACITY: usize = 1;
    const SPONGE_WIDTH: usize = 3;
    const SPONGE_RATE: usize = 2;
    const PERM_ROUNDS_FULL: usize = 63;
    const PERM_ROUNDS_PARTIAL: usize = 0;
    const PERM_HALF_ROUNDS_FULL: usize = 0;
    const PERM_SBOX: u32 = 5;
    const PERM_FULL_MDS: bool = true;
    const PERM_INITIAL_ARK: bool = true;
}

#[derive(Clone)]
pub struct PlonkSpongeConstantsKimchi {}

impl SpongeConstants for PlonkSpongeConstantsKimchi {
    const SPONGE_CAPACITY: usize = 1;
    const SPONGE_WIDTH: usize = 3;
    const SPONGE_RATE: usize = 2;
    const PERM_ROUNDS_FULL: usize = 55;
    const PERM_ROUNDS_PARTIAL: usize = 0;
    const PERM_HALF_ROUNDS_FULL: usize = 0;
    const PERM_SBOX: u32 = 7;
    const PERM_FULL_MDS: bool = true;
    const PERM_INITIAL_ARK: bool = false;
}

/// Cryptographic sponge interface - for hashing an arbitrary amount of
/// data into one or more field elements
pub trait Sponge<Input: Field, Digest> {
    /// Create a new cryptographic sponge using arithmetic sponge `params`
    fn new(params: ArithmeticSpongeParams<Input>) -> Self;

    /// Absorb an array of field elements `x`
    fn absorb(&mut self, x: &[Input]);

    /// Squeeze an output from the sponge
    fn squeeze(&mut self) -> Digest;

    /// Reset the sponge back to its initial state (as if it were just created)
    fn reset(&mut self);
}

pub fn sbox<F: Field, SC: SpongeConstants>(x: F) -> F {
    x.pow([SC::PERM_SBOX as u64])
}

#[derive(Clone, Debug)]
pub enum SpongeState {
    Absorbed(usize),
    Squeezed(usize),
}

#[serde_as]
#[derive(Clone, Serialize, Deserialize, Default, Debug)]
pub struct ArithmeticSpongeParams<F: Field> {
    #[serde_as(as = "Vec<Vec<o1_utils::serialization::SerdeAs>>")]
    pub round_constants: Vec<Vec<F>>,
    #[serde_as(as = "Vec<Vec<o1_utils::serialization::SerdeAs>>")]
    pub mds: Vec<Vec<F>>,
}

#[derive(Clone)]
pub struct ArithmeticSponge<F: Field, SC: SpongeConstants> {
    pub sponge_state: SpongeState,
    rate: usize,
    // TODO(mimoo: an array enforcing the width is better no? or at least an assert somewhere)
    pub state: Vec<F>,
    params: ArithmeticSpongeParams<F>,
    pub constants: std::marker::PhantomData<SC>,
}

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
        for (i, x) in params.round_constants[SC::PERM_HALF_ROUNDS_FULL + SC::PERM_ROUNDS_PARTIAL + r]
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

impl<F: Field, SC: SpongeConstants> ArithmeticSponge<F, SC> {
    pub fn full_round(&mut self, r: usize) {
        full_round::<F, SC>(&self.params, &mut self.state, r);
    }

    fn poseidon_block_cipher(&mut self) {
        poseidon_block_cipher::<F, SC>(&self.params, &mut self.state);
    }
}

impl<F: Field, SC: SpongeConstants> Sponge<F, F> for ArithmeticSponge<F, SC> {
    fn new(params: ArithmeticSpongeParams<F>) -> ArithmeticSponge<F, SC> {
        let capacity = SC::SPONGE_CAPACITY;
        let rate = SC::SPONGE_RATE;

        let mut state = Vec::with_capacity(capacity + rate);

        for _ in 0..(capacity + rate) {
            state.push(F::zero());
        }

        ArithmeticSponge {
            state,
            rate,
            sponge_state: SpongeState::Absorbed(0),
            params,
            constants: std::marker::PhantomData,
        }
    }

    fn absorb(&mut self, x: &[F]) {
        for x in x.iter() {
            match self.sponge_state {
                SpongeState::Absorbed(n) => {
                    if n == self.rate {
                        self.poseidon_block_cipher();
                        self.sponge_state = SpongeState::Absorbed(1);
                        self.state[0].add_assign(x);
                    } else {
                        self.sponge_state = SpongeState::Absorbed(n + 1);
                        self.state[n].add_assign(x);
                    }
                }
                SpongeState::Squeezed(_n) => {
                    self.state[0].add_assign(x);
                    self.sponge_state = SpongeState::Absorbed(1);
                }
            }
        }
    }

    fn squeeze(&mut self) -> F {
        match self.sponge_state {
            SpongeState::Squeezed(n) => {
                if n == self.rate {
                    self.poseidon_block_cipher();
                    self.sponge_state = SpongeState::Squeezed(1);
                    self.state[0]
                } else {
                    self.sponge_state = SpongeState::Squeezed(n + 1);
                    self.state[n]
                }
            }
            SpongeState::Absorbed(_n) => {
                self.poseidon_block_cipher();
                self.sponge_state = SpongeState::Squeezed(1);
                self.state[0]
            }
        }
    }

    fn reset(&mut self) {
        self.state = vec![F::zero(); self.state.len()];
        self.sponge_state = SpongeState::Absorbed(0);
    }
}
