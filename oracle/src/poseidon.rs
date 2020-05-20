/*****************************************************************************************************************

This source file has been copied from
https://gist.githubusercontent.com/imeckler/590adbed68c22288136d2d7987ac364c/raw/915840119a0fdd545b707621026478edc99a3195/poseidon.rs

It implements Poseidon Hash Function primitive

*****************************************************************************************************************/

use algebra::Field;

pub const ROUNDS_FULL: usize = 8;
pub const ROUNDS_PARTIAL: usize = 30;
const HALF_ROUNDS_FULL: usize = ROUNDS_FULL / 2;
pub const SPONGE_CAPACITY: usize = 1;
pub const SPONGE_RATE: usize = 2;

pub trait Sponge<Input, Digest> {
    type Params;
    fn new() -> Self;
    fn absorb(&mut self, params: &Self::Params, x: &[Input]);
    fn squeeze(&mut self, params: &Self::Params) -> Digest;
}

// x^17
fn sbox<F: Field>(x: F) -> F {
    let mut res = x;
    res.square_in_place(); //x^2
    res.square_in_place(); //x^4
    res.square_in_place(); //x^8
    res.square_in_place(); //x^16
    res.mul_assign(&x); // x^17
    res
}

/*
Apply the matrix
[[1, 0, 1],
 [1, 1, 0],
 [0, 1, 1]]
 */
fn apply_near_mds_matrix<F: Field>(v: &Vec<F>) -> Vec<F> {
    vec![v[0] + &v[2], v[0] + &v[1], v[1] + &v[2]]
}

#[derive(Clone)]
enum SpongeState {
    Absorbed(usize),
    Squeezed(usize),
}

#[derive(Clone)]
pub struct ArithmeticSpongeParams<F: Field> {
    pub round_constants: Vec<Vec<F>>,
}

#[derive(Clone)]
pub struct ArithmeticSponge<F: Field> {
    sponge_state: SpongeState,
    rate: usize,
    state: Vec<F>,
}

impl<F: Field> ArithmeticSponge<F> {
    fn poseidon_block_cipher(&mut self, params: &ArithmeticSpongeParams<F>) {
        for r in 0..HALF_ROUNDS_FULL {
            for (i, x) in params.round_constants[r].iter().enumerate() {
                self.state[i].add_assign(x);
            }
            for i in 0..self.state.len() {
                self.state[i] = sbox(self.state[i]);
            }
            let new_state = apply_near_mds_matrix(&self.state);
            for i in 0..new_state.len() {
                self.state[i] = new_state[i];
            }
        }

        for r in 0..ROUNDS_PARTIAL {
            for (i, x) in params.round_constants[HALF_ROUNDS_FULL + r]
                .iter()
                .enumerate()
            {
                self.state[i].add_assign(x);
            }
            self.state[0] = sbox(self.state[0]);
            let new_state = apply_near_mds_matrix(&self.state);
            for i in 0..new_state.len() {
                self.state[i] = new_state[i];
            }
        }

        for r in 0..HALF_ROUNDS_FULL {
            for (i, x) in params.round_constants[HALF_ROUNDS_FULL + ROUNDS_PARTIAL + r]
                .iter()
                .enumerate()
            {
                self.state[i].add_assign(x);
            }
            for i in 0..self.state.len() {
                self.state[i] = sbox(self.state[i]);
            }
            let new_state = apply_near_mds_matrix(&self.state);
            for i in 0..new_state.len() {
                self.state[i] = new_state[i];
            }
        }
    }
}

impl<F: Field> Sponge<F, F> for ArithmeticSponge<F> {
    type Params = ArithmeticSpongeParams<F>;

    fn new() -> ArithmeticSponge<F> {
        let capacity = SPONGE_CAPACITY;
        let rate = SPONGE_RATE;

        let mut state = Vec::with_capacity(capacity + rate);

        for _ in 0..(capacity + rate) {
            state.push(F::zero());
        }

        ArithmeticSponge {
            state,
            rate,
            sponge_state: SpongeState::Absorbed(0),
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
