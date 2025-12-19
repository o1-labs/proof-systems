//! This module implements Poseidon Hash Function primitive

extern crate alloc;

use crate::{
    constants::SpongeConstants,
    permutation::{full_round, poseidon_block_cipher},
};
use alloc::{vec, vec::Vec};
use ark_ff::Field;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

/// Cryptographic sponge interface - for hashing an arbitrary amount of
/// data into one or more field elements
pub trait Sponge<Input: Field, Digest, const FULL_ROUNDS: usize> {
    /// Create a new cryptographic sponge using arithmetic sponge `params`
    fn new(params: &'static ArithmeticSpongeParams<Input, FULL_ROUNDS>) -> Self;

    /// Absorb an array of field elements `x`
    fn absorb(&mut self, x: &[Input]);

    /// Squeeze an output from the sponge
    fn squeeze(&mut self) -> Digest;

    /// Reset the sponge back to its initial state (as if it were just created)
    fn reset(&mut self);
}

pub fn sbox<F: Field, SC: SpongeConstants>(mut x: F) -> F {
    if SC::PERM_SBOX == 7 {
        // This is much faster than using the generic `pow`. Hard-code to get the ~50% speed-up
        // that it gives to hashing.
        let mut square = x;
        square.square_in_place();
        x *= square;
        square.square_in_place();
        x *= square;
        x
    } else {
        x.pow([SC::PERM_SBOX as u64])
    }
}

#[derive(Clone, Debug)]
pub enum SpongeState {
    Absorbed(usize),
    Squeezed(usize),
}

#[derive(Clone, Debug)]
pub struct ArithmeticSpongeParams<
    F: Field + CanonicalSerialize + CanonicalDeserialize,
    const FULL_ROUNDS: usize,
> {
    pub round_constants: [[F; 3]; FULL_ROUNDS],
    pub mds: [[F; 3]; 3],
}

#[derive(Clone)]
pub struct ArithmeticSponge<F: Field, SC: SpongeConstants, const FULL_ROUNDS: usize> {
    pub sponge_state: SpongeState,
    rate: usize,
    // TODO(mimoo: an array enforcing the width is better no? or at least an assert somewhere)
    pub state: Vec<F>,
    params: &'static ArithmeticSpongeParams<F, FULL_ROUNDS>,
    pub constants: core::marker::PhantomData<SC>,
}

impl<F: Field, SC: SpongeConstants, const FULL_ROUNDS: usize> ArithmeticSponge<F, SC, FULL_ROUNDS> {
    pub fn full_round(&mut self, r: usize) {
        full_round::<F, SC, FULL_ROUNDS>(self.params, &mut self.state, r);
    }

    pub fn poseidon_block_cipher(&mut self) {
        poseidon_block_cipher::<F, SC, FULL_ROUNDS>(self.params, &mut self.state);
    }
}

impl<F: Field, SC: SpongeConstants, const FULL_ROUNDS: usize> Sponge<F, F, FULL_ROUNDS>
    for ArithmeticSponge<F, SC, FULL_ROUNDS>
{
    fn new(params: &'static ArithmeticSpongeParams<F, FULL_ROUNDS>) -> Self {
        let capacity = SC::SPONGE_CAPACITY;
        let rate = SC::SPONGE_RATE;

        let mut state = Vec::with_capacity(capacity + rate);

        for _ in 0..(capacity + rate) {
            state.push(F::zero());
        }

        Self {
            state,
            rate,
            sponge_state: SpongeState::Absorbed(0),
            params,
            constants: core::marker::PhantomData,
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
