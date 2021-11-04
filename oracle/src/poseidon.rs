/*****************************************************************************************************************

This file implements Poseidon Hash Function primitive

*****************************************************************************************************************/

use ark_ff::Field;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

pub trait SpongeConstants {
    const ROUNDS_FULL: usize;
    const ROUNDS_PARTIAL: usize;
    const HALF_ROUNDS_FULL: usize;
    const SPONGE_WIDTH: usize = 3;
    const SPONGE_CAPACITY: usize = 1;
    const SPONGE_RATE: usize = 2;
    const SPONGE_BOX: usize;
    const FULL_MDS: bool;
    const INITIAL_ARK: bool;
}

#[derive(Clone)]
pub struct PlonkSpongeConstantsBasic {}

impl SpongeConstants for PlonkSpongeConstantsBasic {
    const ROUNDS_FULL: usize = 63;
    const ROUNDS_PARTIAL: usize = 0;
    const HALF_ROUNDS_FULL: usize = 0;
    const SPONGE_CAPACITY: usize = 1;
    const SPONGE_WIDTH: usize = 3;
    const SPONGE_RATE: usize = 2;
    const SPONGE_BOX: usize = 5;
    const FULL_MDS: bool = true;
    const INITIAL_ARK: bool = true;
}

#[derive(Clone)]
pub struct PlonkSpongeConstants5W {}

impl SpongeConstants for PlonkSpongeConstants5W {
    const ROUNDS_FULL: usize = 53;
    const ROUNDS_PARTIAL: usize = 0;
    const HALF_ROUNDS_FULL: usize = 0;
    const SPONGE_CAPACITY: usize = 1;
    const SPONGE_WIDTH: usize = 5;
    const SPONGE_RATE: usize = 4;
    const SPONGE_BOX: usize = 7;
    const FULL_MDS: bool = true;
    const INITIAL_ARK: bool = false;
}

#[derive(Clone)]
pub struct PlonkSpongeConstants3W {}

impl SpongeConstants for PlonkSpongeConstants3W {
    const ROUNDS_FULL: usize = 54;
    const ROUNDS_PARTIAL: usize = 0;
    const HALF_ROUNDS_FULL: usize = 0;
    const SPONGE_CAPACITY: usize = 1;
    const SPONGE_WIDTH: usize = 3;
    const SPONGE_RATE: usize = 2;
    const SPONGE_BOX: usize = 7;
    const FULL_MDS: bool = true;
    const INITIAL_ARK: bool = false;
}

#[derive(Clone)]
pub struct PlonkSpongeConstants15W {}

impl SpongeConstants for PlonkSpongeConstants15W {
    const ROUNDS_FULL: usize = 55;
    const ROUNDS_PARTIAL: usize = 0;
    const HALF_ROUNDS_FULL: usize = 0;
    const SPONGE_CAPACITY: usize = 1;
    const SPONGE_WIDTH: usize = 3;
    const SPONGE_RATE: usize = 2;
    const SPONGE_BOX: usize = 7;
    const FULL_MDS: bool = true;
    const INITIAL_ARK: bool = false;
}

pub trait Sponge<Input: Field, Digest> {
    fn new(params: ArithmeticSpongeParams<Input>) -> Self;
    fn absorb(&mut self, x: &[Input]);
    fn squeeze(&mut self) -> Digest;
}

pub fn sbox<F: Field, SC: SpongeConstants>(x: F) -> F {
    x.pow([SC::SPONGE_BOX as u64])
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

impl<F: Field, SC: SpongeConstants> ArithmeticSponge<F, SC> {
    fn apply_mds_matrix(&mut self) {
        self.state = if SC::FULL_MDS {
            self.params
                .mds
                .iter()
                .map(|m| {
                    self.state
                        .iter()
                        .zip(m.iter())
                        .fold(F::zero(), |x, (s, &m)| m * s + x)
                })
                .collect()
        } else {
            vec![
                self.state[0] + &self.state[2],
                self.state[0] + &self.state[1],
                self.state[1] + &self.state[2],
            ]
        };
    }

    /// Performs a single full round (given the round number) for the sponge.
    /// Note that if INITIAL_ARK is set in the parameters, calling full round will not be enough to manually implement the sponge.
    pub fn full_round(&mut self, r: usize) {
        // TODO(mimoo): ideally this should be enforced in the type of the state itself
        assert!(self.state.len() == SC::SPONGE_WIDTH);
        for i in 0..self.state.len() {
            self.state[i] = sbox::<F, SC>(self.state[i]);
        }
        self.apply_mds_matrix();
        for (i, x) in self.params.round_constants[r].iter().enumerate() {
            self.state[i].add_assign(x);
        }
    }

    fn half_rounds(&mut self) {
        for r in 0..SC::HALF_ROUNDS_FULL {
            for (i, x) in self.params.round_constants[r].iter().enumerate() {
                self.state[i].add_assign(x);
            }
            for i in 0..self.state.len() {
                self.state[i] = sbox::<F, SC>(self.state[i]);
            }
            self.apply_mds_matrix();
        }

        for r in 0..SC::ROUNDS_PARTIAL {
            for (i, x) in self.params.round_constants[SC::HALF_ROUNDS_FULL + r]
                .iter()
                .enumerate()
            {
                self.state[i].add_assign(x);
            }
            self.state[0] = sbox::<F, SC>(self.state[0]);
            self.apply_mds_matrix();
        }

        for r in 0..SC::HALF_ROUNDS_FULL {
            for (i, x) in self.params.round_constants[SC::HALF_ROUNDS_FULL + SC::ROUNDS_PARTIAL + r]
                .iter()
                .enumerate()
            {
                self.state[i].add_assign(x);
            }
            for i in 0..self.state.len() {
                self.state[i] = sbox::<F, SC>(self.state[i]);
            }
            self.apply_mds_matrix();
        }
    }

    fn poseidon_block_cipher(&mut self) {
        if SC::HALF_ROUNDS_FULL == 0 {
            if SC::INITIAL_ARK == true {
                for (i, x) in self.params.round_constants[0].iter().enumerate() {
                    self.state[i].add_assign(x);
                }
                for r in 0..SC::ROUNDS_FULL {
                    self.full_round(r + 1);
                }
            } else {
                for r in 0..SC::ROUNDS_FULL {
                    self.full_round(r);
                }
            }
        } else {
            self.half_rounds();
        }
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
            println!("Rabsorb {}", x);
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
}
