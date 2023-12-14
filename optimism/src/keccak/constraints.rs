use crate::keccak::{
    column::KeccakColumn,
    environment::{KeccakEnv, KeccakEnvironment},
    BoolOps,
};
use ark_ff::Field;
use kimchi::circuits::polynomials::keccak::{DIM, QUARTERS};

use super::{E, WORDS_IN_HASH};

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

        // LOOKUP CONSTRAINTS
    }
}
