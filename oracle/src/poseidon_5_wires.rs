/*****************************************************************************************************************

This file implements Poseidon Hash Function primitive

*****************************************************************************************************************/

use algebra::Field;
use super::poseidon::{ArithmeticSpongeParams, Sponge, SpongeState,
                      SpongeConstants};

#[derive(Clone)]
pub struct PlonkSpongeConstants {
}

impl SpongeConstants for PlonkSpongeConstants {
    const ROUNDS_FULL: usize = 53;
    const ROUNDS_PARTIAL: usize = 0;
    const HALF_ROUNDS_FULL: usize = 0;
    const SPONGE_CAPACITY: usize = 1;
    const SPONGE_WIDTH: usize = 5;
    const SPONGE_RATE: usize = 4;
    const SPONGE_BOX: usize = 7;
    const FULL_MDS: bool = true;
}

pub fn sbox<F : Field, SC: SpongeConstants>(x: F) -> F {
    x.pow([SC::SPONGE_BOX as u64])
}

#[derive(Clone)]
pub struct ArithmeticSponge<F: Field, SC: SpongeConstants> {
    pub sponge_state: SpongeState,
    rate: usize,
    pub state: Vec<F>,
    pub constants: std::marker::PhantomData<SC>,
}

impl<F: Field, SC: SpongeConstants> ArithmeticSponge<F, SC> {
    fn apply_mds_matrix(&mut self, params: &ArithmeticSpongeParams<F>) {
        self.state = if SC::FULL_MDS
        {
            params.mds.iter().
                map(|m| self.state.iter().zip(m.iter()).fold(F::zero(), |x, (s, &m)| m * s + x)).collect()
        }
        else
        {
            vec!
            [
                self.state[0] + &self.state[2],
                self.state[0] + &self.state[1],
                self.state[1] + &self.state[2]
            ]
        };
    }

    pub fn full_round(&mut self, r: usize, params: &ArithmeticSpongeParams<F>) {
        for i in 0..self.state.len() {
            self.state[i] = sbox::<F, SC>(self.state[i]);
        }
        self.apply_mds_matrix(params);
        for (i, x) in params.round_constants[r].iter().enumerate() {
            self.state[i].add_assign(x);
        }
    }

    fn half_rounds(&mut self, params: &ArithmeticSpongeParams<F>) {
        for r in 0..SC::HALF_ROUNDS_FULL {
            for (i, x) in params.round_constants[r].iter().enumerate() {
                self.state[i].add_assign(x);
            }
            for i in 0..self.state.len() {
                self.state[i] = sbox::<F, SC>(self.state[i]);
            }
            self.apply_mds_matrix(params);
        }

        for r in 0..SC::ROUNDS_PARTIAL {
            for (i, x) in params.round_constants[SC::HALF_ROUNDS_FULL + r]
                .iter()
                .enumerate()
            {
                self.state[i].add_assign(x);
            }
            self.state[0] = sbox::<F, SC>(self.state[0]);
            self.apply_mds_matrix(params);
        }

        for r in 0..SC::HALF_ROUNDS_FULL {
            for (i, x) in params.round_constants[SC::HALF_ROUNDS_FULL + SC::ROUNDS_PARTIAL + r]
                .iter()
                .enumerate()
            {
                self.state[i].add_assign(x);
            }
            for i in 0..self.state.len() {
                self.state[i] = sbox::<F, SC>(self.state[i]);
            }
            self.apply_mds_matrix(params);
        }
    }

    fn poseidon_block_cipher(&mut self, params: &ArithmeticSpongeParams<F>) {
        if SC::HALF_ROUNDS_FULL == 0 {
            for r in 0..SC::ROUNDS_FULL {
                self.full_round(r, params);
            }
        } else {
            self.half_rounds(params);
        }
    }
}

impl<F: Field, SC: SpongeConstants> Sponge<F, F> for ArithmeticSponge<F, SC> {
    type Params = ArithmeticSpongeParams<F>;

    fn new() -> ArithmeticSponge<F, SC> {
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
            constants: std::marker::PhantomData,
        }
    }

    fn absorb(&mut self, params: &ArithmeticSpongeParams<F>, x: &[F]) {
        for x in x.iter()
        {
            match self.sponge_state {
                SpongeState::Absorbed(n) => {
                    if n == self.rate {
                        self.poseidon_block_cipher(params);
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

    fn squeeze(&mut self, params: &ArithmeticSpongeParams<F>) -> F {
        match self.sponge_state {
            SpongeState::Squeezed(n) => {
                if n == self.rate {
                    self.poseidon_block_cipher(params);
                    self.sponge_state = SpongeState::Squeezed(1);
                    self.state[0]
                } else {
                    self.sponge_state = SpongeState::Squeezed(n + 1);
                    self.state[n]
                }
            }
            SpongeState::Absorbed(_n) => {
                self.poseidon_block_cipher(params);
                self.sponge_state = SpongeState::Squeezed(1);
                self.state[0]
            }
        }
    }
}
