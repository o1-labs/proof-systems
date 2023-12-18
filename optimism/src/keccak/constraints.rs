use crate::keccak::{
    column::KeccakColumn,
    environment::{KeccakEnv, KeccakEnvironment},
    {ArithOps, BoolOps, E, WORDS_IN_HASH},
};
use ark_ff::Field;
use kimchi::circuits::polynomials::keccak::{DIM, OFF, QUARTERS};

pub trait Constraints {
    type Column;
    type Variable: std::ops::Mul<Self::Variable, Output = Self::Variable>
        + std::ops::Add<Self::Variable, Output = Self::Variable>
        + std::ops::Sub<Self::Variable, Output = Self::Variable>
        + Clone;
    type Fp: std::ops::Neg<Output = Self::Fp>;

    fn constrain(&mut self, x: Self::Variable);

    fn constraints(&mut self);
}

impl<Fp: Field> Constraints for KeccakEnv<Fp> {
    type Column = KeccakColumn;
    type Variable = E<Fp>;
    type Fp = Fp;

    fn constrain(&mut self, x: Self::Variable) {
        self.constraints.push(x);
    }

    fn constraints(&mut self) {
        // CORRECTNESS OF FLAGS
        {
            // TODO: remove redundancy if any

            // Booleanity of sponge flags
            {
                // Absorb is either true or false
                self.constrain(Self::boolean(self.absorb()));
                // Squeeze is either true or false
                self.constrain(Self::boolean(self.squeeze()));
                // Root is either true or false
                self.constrain(Self::boolean(self.root()));
                // Pad is either true or false
                self.constrain(Self::boolean(self.pad()));
            }
            // Mutually exclusiveness of flags
            {
                // Squeeze and Root are not both true
                self.constrain(Self::either_false(self.squeeze(), self.root()));
                // Squeeze and Pad are not both true
                self.constrain(Self::either_false(self.squeeze(), self.pad()));
                // Round and Pad are not both true
                self.constrain(Self::either_false(self.is_round(), self.pad()));
                // Round and Root are not both true
                self.constrain(Self::either_false(self.is_round(), self.root()));
                // Absorb and Squeeze cannot happen at the same time
                self.constrain(Self::either_false(self.absorb(), self.squeeze()));
                // Round and Sponge cannot happen at the same time
                self.constrain(Self::either_false(self.round(), self.is_sponge()));
                // Trivially, is_sponge and is_round are mutually exclusive
            }
        }

        // SPONGE CONSTRAINTS
        {
            for z in self.sponge_zeros() {
                // Absorb phase pads with zeros the new state
                self.constrain(self.absorb() * z.clone());
            }
            for i in 0..QUARTERS * DIM * DIM {
                // In first absorb, root state is all zeros
                self.constrain(self.root() * self.old_state(i));
                // Absorbs the new block by performing XOR with the old state
                self.constrain(
                    self.absorb() * (self.next_state(i) - (self.old_state(i) + self.new_block(i))),
                );
                // In absorb, Check shifts correspond to the decomposition of the new state
                self.constrain(
                    self.absorb()
                        * (self.new_block(i)
                            - Self::from_shifts(
                                &self.keccak_state.sponge_shifts,
                                Some(i),
                                None,
                                None,
                                None,
                            )),
                );
            }
            for i in 0..QUARTERS * WORDS_IN_HASH {
                // In squeeze, Check shifts correspond to the 256-bit prefix digest of the old state (current)
                self.constrain(
                    self.squeeze()
                        * (self.old_state(i)
                            - Self::from_shifts(
                                &self.keccak_state.sponge_shifts,
                                Some(i),
                                None,
                                None,
                                None,
                            )),
                );
            }
            // TODO: check padding with lookups
        }

        // ROUND CONSTRAINTS
        {
            // DEFINE ROUND CONSTANT
            // TODO: lookup round and sparse constants
            // self.round() = [0..24)

            // Define vectors storing expressions which are not in the witness layout for efficiency
            let mut state_c: Vec<Vec<Self::Variable>> =
                vec![vec![Self::constant(Fp::zero()); QUARTERS]; DIM];
            let mut state_d: Vec<Vec<Self::Variable>> =
                vec![vec![Self::constant(Fp::zero()); QUARTERS]; DIM];
            let mut state_e: Vec<Vec<Vec<Self::Variable>>> =
                vec![vec![vec![Self::constant(Fp::zero()); QUARTERS]; DIM]; DIM];
            let mut state_b: Vec<Vec<Vec<Self::Variable>>> =
                vec![vec![vec![Self::constant(Fp::zero()); QUARTERS]; DIM]; DIM];
            let mut state_f: Vec<Vec<Vec<Self::Variable>>> =
                vec![vec![vec![Self::constant(Fp::zero()); QUARTERS]; DIM]; DIM];

            // STEP theta: 5 * ( 3 + 4 * 1 ) = 35 constraints
            for x in 0..DIM {
                let word_c = Self::from_quarters(&self.keccak_state.theta_dense_c, None, x);
                let rem_c = Self::from_quarters(&self.keccak_state.theta_remainder_c, None, x);
                let rot_c = Self::from_quarters(&self.keccak_state.theta_dense_rot_c, None, x);

                self.constrain(
                    self.is_round()
                        * (word_c * Self::two_pow(1)
                            - (self.quotient_c(x) * Self::two_pow(64) + rem_c.clone())),
                );
                self.constrain(self.is_round() * (rot_c - (self.quotient_c(x) + rem_c)));
                self.constrain(self.is_round() * (Self::boolean(self.quotient_c(x))));

                for q in 0..QUARTERS {
                    state_c[x][q] = self.state_a(0, x, q)
                        + self.state_a(1, x, q)
                        + self.state_a(2, x, q)
                        + self.state_a(3, x, q)
                        + self.state_a(4, x, q);
                    self.constrain(
                        self.is_round()
                            * (state_c[x][q].clone()
                                - Self::from_shifts(
                                    &self.keccak_state.theta_shifts_c,
                                    None,
                                    None,
                                    Some(x),
                                    Some(q),
                                )),
                    );

                    state_d[x][q] = self.shifts_c(0, (x + DIM - 1) % DIM, q)
                        + self.expand_rot_c((x + 1) % DIM, q);

                    for (y, column_e) in state_e.iter_mut().enumerate() {
                        column_e[x][q] = self.state_a(y, x, q) + state_d[x][q].clone();
                    }
                }
            } // END theta

            // STEP pirho: 5 * 5 * (2 + 4 * 1) = 150 constraints
            for (y, col) in OFF.iter().enumerate() {
                for (x, off) in col.iter().enumerate() {
                    let word_e = Self::from_quarters(&self.keccak_state.pi_rho_dense_e, Some(y), x);
                    let quo_e =
                        Self::from_quarters(&self.keccak_state.pi_rho_quotient_e, Some(y), x);
                    let rem_e =
                        Self::from_quarters(&self.keccak_state.pi_rho_remainder_e, Some(y), x);
                    let rot_e =
                        Self::from_quarters(&self.keccak_state.pi_rho_dense_rot_e, Some(y), x);

                    self.constrain(
                        word_e * Self::two_pow(*off)
                            - (quo_e.clone() * Self::two_pow(64) + rem_e.clone()),
                    );
                    self.constrain(self.is_round() * (rot_e - (quo_e.clone() + rem_e)));

                    for q in 0..QUARTERS {
                        self.constrain(
                            self.is_round()
                                * (state_e[y][x][q].clone()
                                    - Self::from_shifts(
                                        &self.keccak_state.pi_rho_shifts_e,
                                        None,
                                        Some(y),
                                        Some(x),
                                        Some(q),
                                    )),
                        );
                        state_b[(2 * x + 3 * y) % DIM][y][q] = self.expand_rot_e(y, x, q);
                    }
                }
            } // END pirho

            // STEP chi: 4 * 5 * 5 * 2 = 200 constraints
            for q in 0..QUARTERS {
                for x in 0..DIM {
                    for y in 0..DIM {
                        let not = Self::constant(Fp::from(0x1111111111111111u64))
                            - self.shifts_b(0, y, (x + 1) % DIM, q);
                        let sum = not + self.shifts_b(0, y, (x + 2) % DIM, q);
                        let and = self.shifts_sum(1, y, x, q);

                        self.constrain(
                            self.is_round()
                                * (state_b[y][x][q].clone()
                                    - Self::from_shifts(
                                        &self.keccak_state.chi_shifts_b,
                                        None,
                                        Some(y),
                                        Some(x),
                                        Some(q),
                                    )),
                        );
                        self.constrain(
                            self.is_round()
                                * (sum
                                    - Self::from_shifts(
                                        &self.keccak_state.chi_shifts_sum,
                                        None,
                                        Some(y),
                                        Some(x),
                                        Some(q),
                                    )),
                        );
                        state_f[y][x][q] = self.shifts_b(0, y, x, q) + and;
                    }
                }
            } // END chi
        }

        // LOOKUP CONSTRAINTS
    }
}
