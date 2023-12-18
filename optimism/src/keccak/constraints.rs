use crate::keccak::{
    column::KeccakColumn,
    environment::{KeccakEnv, KeccakEnvironment},
    BoolOps,
};
use ark_ff::Field;

use super::E;

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

        // ROUND CONSTRAINTS

        // LOOKUP CONSTRAINTS
    }
}
