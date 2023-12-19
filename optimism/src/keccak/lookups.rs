use ark_ff::Field;

use crate::mips::interpreter::Lookup;

use super::{column::KeccakColumn, environment::KeccakEnv, E};

pub(crate) trait Lookups {
    type Column;
    type Variable: std::ops::Mul<Self::Variable, Output = Self::Variable>
        + std::ops::Add<Self::Variable, Output = Self::Variable>
        + std::ops::Sub<Self::Variable, Output = Self::Variable>
        + Clone;
    type Fp: std::ops::Neg<Output = Self::Fp>;

    /// Adds a given lookup to the environment
    fn add_lookup(&mut self, lookup: Lookup<Self::Variable>);

    /// Adds all lookups of Self
    fn lookups(&mut self);
}

impl<Fp: Field> Lookups for KeccakEnv<Fp> {
    type Column = KeccakColumn;
    type Variable = E<Fp>;
    type Fp = Fp;

    fn add_lookup(&mut self, lookup: Lookup<Self::Variable>) {
        self.lookups.push(lookup);
    }

    fn lookups(&mut self) {
        // TODO: preimage lookups (somewhere else)

        // SPONGE LOOKUPS
        {
            // PADDING LOOKUPS
            {}
            // OTHER LOOKUPS
            {}
        }

        // ROUND LOOKUPS
        {
            // THETA LOOKUPS
            {}
            // PIRHO LOOKUPS
            {}
            // CHI LOOKUPS
            {}
            // IOTA LOOKUPS
            {}
        }
    }
}
