//! This module contains the constraints for one Keccak step.
use crate::{
    keccak::{
        column::{KeccakColumn, PAD_SUFFIX_LEN},
        environment::{KeccakEnv, KeccakEnvironment},
        {ArithOps, BoolOps, E, WORDS_IN_HASH},
    },
    lookup::Lookups,
};
use ark_ff::Field;
use kimchi::circuits::{
    expr::{Expr, ExprInner, Variable},
    gate::CurrOrNext,
    polynomials::keccak::{
        constants::{DIM, QUARTERS, RATE_IN_BYTES, SPONGE_ZEROS_LEN},
        OFF,
    },
};

/// This trait contains the constraints for one Keccak step.
pub trait Constraints {
    type Column;
    type Variable: std::ops::Mul<Self::Variable, Output = Self::Variable>
        + std::ops::Add<Self::Variable, Output = Self::Variable>
        + std::ops::Sub<Self::Variable, Output = Self::Variable>
        + Clone;
    type Fp: std::ops::Neg<Output = Self::Fp>;

    /// Returns the variable corresponding to a given column alias.
    fn variable(&self, column: Self::Column) -> Self::Variable;

    /// Adds one constraint to the environment.
    fn constrain(&mut self, x: Self::Variable);

    /// Adds all 887 constraints to the environment and triggers read lookups:
    /// - 143 constraints of degree 1
    /// - 739 constraints of degree 2
    /// - 5 constraints of degree 5
    fn constraints(&mut self);
}

impl<Fp: Field> Constraints for KeccakEnv<Fp> {
    type Column = KeccakColumn;
    type Variable = E<Fp>;
    type Fp = Fp;

    fn variable(&self, column: Self::Column) -> Self::Variable {
        // Despite `KeccakWitness` containing both `curr` and `next` fields,
        // the Keccak step spans across one row only.
        Expr::Atom(ExprInner::Cell(Variable {
            col: column,
            row: CurrOrNext::Curr,
        }))
    }

    fn constrain(&mut self, x: Self::Variable) {
        self.constraints.push(x);
    }

    fn constraints(&mut self) {
        // CORRECTNESS OF FLAGS: 144 CONSTRAINTS
        // - 143 constraints of degree 1
        // - 1 constraint of degree 2
        {
            // Booleanity of sponge flags: 139 constraints of degree 1
            {
                // Absorb is either true or false
                self.constrain(Self::is_boolean(self.is_absorb()));
                // Squeeze is either true or false
                self.constrain(Self::is_boolean(self.is_squeeze()));
                // Root is either true or false
                self.constrain(Self::is_boolean(self.is_root()));
                for i in 0..RATE_IN_BYTES {
                    // Bytes are either involved on padding or not
                    self.constrain(Self::is_boolean(self.in_padding(i)));
                }
            }
            // Mutual exclusivity of flags: 5 constraints:
            // - 4 of degree 1
            // - 1 of degree 2
            {
                // Squeeze and Root are not both true
                self.constrain(Self::either_zero(self.is_squeeze(), self.is_root()));
                // Squeeze and Pad are not both true
                self.constrain(Self::either_zero(self.is_squeeze(), self.is_pad()));
                // Round and Pad are not both true
                self.constrain(Self::either_zero(self.is_round(), self.is_pad()));
                // Round and Root are not both true
                self.constrain(Self::either_zero(self.is_round(), self.is_root()));
                // Absorb and Squeeze cannot happen at the same time.
                // Equivalent to is_boolean(is_sponge())
                self.constrain(Self::either_zero(self.is_absorb(), self.is_squeeze()));
                // Trivially, is_sponge and is_round are mutually exclusive
            }
        }

        // SPONGE CONSTRAINTS: 32 + 3*100 + 16 + 6 = 354 CONSTRAINTS OF DEGREE 2
        {
            for i in 0..SPONGE_ZEROS_LEN {
                // Absorb phase pads with zeros the new state
                self.constrain(self.is_absorb() * self.sponge_zeros()[i].clone());
            }
            for i in 0..QUARTERS * DIM * DIM {
                // In first absorb, root state is all zeros
                self.constrain(self.is_root() * self.old_state(i).clone());
                // Absorbs the new block by performing XOR with the old state
                self.constrain(
                    self.is_absorb()
                        * (self.xor_state(i).clone()
                            - (self.old_state(i).clone() + self.new_state(i).clone())),
                );
                // In absorb, Check shifts correspond to the decomposition of the new state
                self.constrain(
                    self.is_absorb()
                        * (self.new_state(i).clone()
                            - Self::from_shifts(
                                &self.vec_sponge_shifts(),
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
                    self.is_squeeze()
                        * (self.old_state(i).clone()
                            - Self::from_shifts(
                                &self.vec_sponge_shifts(),
                                Some(i),
                                None,
                                None,
                                None,
                            )),
                );
            }
            // Check that the padding is located at the end of the message
            let pad_at_end = (0..RATE_IN_BYTES).fold(Self::zero(), |acc, i| {
                acc * Self::two() + self.sponge_byte(i)
            });
            self.constrain(self.is_pad() * (self.two_to_pad() - Self::one() - pad_at_end));
            // Check that the padding value is correct
            for i in 0..PAD_SUFFIX_LEN {
                self.constrain(self.is_pad() * (self.block_in_padding(i) - self.pad_suffix(i)));
            }
        }

        // ROUND CONSTRAINTS: 35 + 150 + 200 + 4 = 389 CONSTRAINTS
        // - 384 constraints of degree 2
        // - 5 constraints of degree 3
        {
            // Define vectors storing expressions which are not in the witness layout for efficiency
            let mut state_c = vec![vec![Self::zero(); QUARTERS]; DIM];
            let mut state_d = vec![vec![Self::zero(); QUARTERS]; DIM];
            let mut state_e = vec![vec![vec![Self::zero(); QUARTERS]; DIM]; DIM];
            let mut state_b = vec![vec![vec![Self::zero(); QUARTERS]; DIM]; DIM];
            let mut state_f = vec![vec![vec![Self::zero(); QUARTERS]; DIM]; DIM];

            // STEP theta: 5 * ( 3 + 4 * 1 ) = 35 constraints
            // - 30 constraints of degree 2
            // - 5 constraints of degree 3
            for x in 0..DIM {
                let word_c = Self::from_quarters(&self.vec_dense_c(), None, x);
                let rem_c = Self::from_quarters(&self.vec_remainder_c(), None, x);
                let rot_c = Self::from_quarters(&self.vec_dense_rot_c(), None, x);

                self.constrain(
                    self.is_round()
                        * (word_c * Self::two_pow(1)
                            - (self.quotient_c(x) * Self::two_pow(64) + rem_c.clone())),
                );
                self.constrain(self.is_round() * (rot_c - (self.quotient_c(x) + rem_c)));
                self.constrain(self.is_round() * (Self::is_boolean(self.quotient_c(x))));

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
                                    &self.vec_shifts_c(),
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

            // STEP pirho: 5 * 5 * (2 + 4 * 1) = 150 constraints of degree 2
            for (y, col) in OFF.iter().enumerate() {
                for (x, off) in col.iter().enumerate() {
                    let word_e = Self::from_quarters(&self.vec_dense_e(), Some(y), x);
                    let quo_e = Self::from_quarters(&self.vec_quotient_e(), Some(y), x);
                    let rem_e = Self::from_quarters(&self.vec_remainder_e(), Some(y), x);
                    let rot_e = Self::from_quarters(&self.vec_dense_rot_e(), Some(y), x);

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
                                        &self.vec_shifts_e(),
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

            // STEP chi: 4 * 5 * 5 * 2 = 200 constraints of degree 2
            for q in 0..QUARTERS {
                for x in 0..DIM {
                    for y in 0..DIM {
                        let not = Self::constant(0x1111111111111111u64)
                            - self.shifts_b(0, y, (x + 1) % DIM, q);
                        let sum = not + self.shifts_b(0, y, (x + 2) % DIM, q);
                        let and = self.shifts_sum(1, y, x, q);

                        self.constrain(
                            self.is_round()
                                * (state_b[y][x][q].clone()
                                    - Self::from_shifts(
                                        &self.vec_shifts_b(),
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
                                        &self.vec_shifts_sum(),
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

            // STEP iota: 4 constraints of degree 2
            for (q, c) in self.round_constants().to_vec().iter().enumerate() {
                self.constrain(
                    self.is_round()
                        * (self.state_g(q).clone() - (state_f[0][0][q].clone() + c.clone())),
                );
            } // END iota
        }

        // READ LOOKUP CONSTRAINTS
        self.lookups();
    }
}
