use super::{
    column::KeccakColumn,
    environment::{KeccakEnv, KeccakEnvironment},
    ArithOps, E,
};
use crate::mips::interpreter::{Lookup, LookupTable, Sign, Signed};
use ark_ff::{Field, One};
use kimchi::circuits::polynomials::keccak::{SHIFTS_LEN, STATE_LEN};

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
                        sign: Sign::Neg,
                        magnitude: Self::Variable::one(),
                    },
                    table_id: LookupTable::PadLookup,
                    value: vec![
                        self.keccak_state[KeccakColumn::FlagLength].clone(),
                        self.two_to_pad(),
                        self.pad_suffix(0),
                        self.pad_suffix(1),
                        self.pad_suffix(2),
                        self.pad_suffix(3),
                        self.pad_suffix(4),
                    ],
                })
                // Note: When FlagLength=0, TwoToPad=1, and all PadSuffix=0
            }
            // BYTES LOOKUPS
            {
                // Bytes are <2^8
                for i in 0..200 {
                    self.add_lookup(Lookup {
                        numerator: Signed {
                            sign: Sign::Neg,
                            magnitude: Self::Variable::one(),
                        },
                        table_id: LookupTable::ByteLookup,
                        value: vec![self.sponge_bytes(i)],
                    })
                }
            }
            // SHIFTS LOOKUPS
            {
                // Shifts1, Shifts2, Shifts3 are in the Sparse table
                for i in 100..SHIFTS_LEN {
                    self.add_lookup(Lookup {
                        numerator: Signed {
                            sign: Sign::Neg,
                            magnitude: Self::Variable::one(),
                        },
                        table_id: LookupTable::SparseLookup,
                        value: vec![self.sponge_shift(i)],
                    })
                }
                // Shifts0 together with Bits composition by pairs are in the Reset table
                for i in 0..STATE_LEN {
                    self.add_lookup(Lookup {
                        numerator: Signed {
                            sign: Sign::Neg,
                            magnitude: Self::Variable::one(),
                        },
                        table_id: LookupTable::ResetLookup,
                        value: vec![
                            self.sponge_bytes(2 * i)
                                + self.sponge_bytes(2 * i + 1) * Self::two_pow(8),
                            self.sponge_shift(i),
                        ],
                    })
                }
            }
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
