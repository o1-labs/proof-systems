use crate::mips::interpreter::{Lookup, LookupTable, Sign, Signed};
use ark_ff::{Field, One};

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
            {
                // Power of two corresponds to 2^pad_length
                // Pad suffixes correspond to 10*1 rule
                self.add_lookup(Lookup {
                    numerator: Signed {
                        sign: Sign::Pos,
                        magnitude: Self::Variable::one(),
                    },
                    table_id: LookupTable::PadLookup,
                    value: vec![
                        self.keccak_state[KeccakColumn::FlagLength].clone(),
                        self.keccak_state[KeccakColumn::TwoToPad].clone(),
                        self.keccak_state[KeccakColumn::PadSuffix(0)].clone(),
                        self.keccak_state[KeccakColumn::PadSuffix(1)].clone(),
                        self.keccak_state[KeccakColumn::PadSuffix(2)].clone(),
                        self.keccak_state[KeccakColumn::PadSuffix(3)].clone(),
                        self.keccak_state[KeccakColumn::PadSuffix(4)].clone(),
                    ],
                })
                // Note: When FlagLength=0, TwoToPad=1, and all PadSuffix=0
            }
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
