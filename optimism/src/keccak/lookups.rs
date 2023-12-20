use super::{
    column::KeccakColumn,
    environment::{KeccakEnv, KeccakEnvironment},
    ArithOps, E,
};
use crate::mips::interpreter::{Lookup, LookupTable, Sign, Signed};
use ark_ff::{Field, One};
use kimchi::circuits::polynomials::keccak::constants::{QUARTERS, SHIFTS_LEN, STATE_LEN};

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
            {
                for i in 0..20 {
                    // Check ThetaShiftC0 is the expansion of ThetaDenseC
                    self.add_lookup(Lookup {
                        numerator: Signed {
                            sign: Sign::Neg,
                            magnitude: Self::Variable::one(),
                        },
                        table_id: LookupTable::ResetLookup,
                        value: vec![
                            self.keccak_state.theta_dense_c[i].clone(),
                            self.keccak_state.theta_shifts_c[i].clone(),
                        ],
                    });
                    // Check ThetaExpandRotC is the expansion of ThetaDenseRotC
                    self.add_lookup(Lookup {
                        numerator: Signed {
                            sign: Sign::Neg,
                            magnitude: Self::Variable::one(),
                        },
                        table_id: LookupTable::ResetLookup,
                        value: vec![
                            self.keccak_state.theta_dense_rot_c[i].clone(),
                            self.keccak_state.theta_expand_rot_c[i].clone(),
                        ],
                    });
                    // Check that the rest of ThetaShiftsC are in the Sparse table
                    for j in 1..4 {
                        self.add_lookup(Lookup {
                            numerator: Signed {
                                sign: Sign::Neg,
                                magnitude: Self::Variable::one(),
                            },
                            table_id: LookupTable::SparseLookup,
                            value: vec![self.keccak_state.theta_shifts_c[i + 20 * j].clone()],
                        });
                    }
                    // Check that ThetaRemainderC < 2^64
                    self.add_lookup(Lookup {
                        numerator: Signed {
                            sign: Sign::Neg,
                            magnitude: Self::Variable::one(),
                        },
                        table_id: LookupTable::RangeCheck16Lookup,
                        value: vec![self.keccak_state.theta_remainder_c[i].clone()],
                    });
                }
            }
            // PIRHO LOOKUPS
            {
                for i in 0..STATE_LEN {
                    // Check PiRhoShift0E is the expansion of PiRhoDenseE
                    self.add_lookup(Lookup {
                        numerator: Signed {
                            sign: Sign::Neg,
                            magnitude: Self::Variable::one(),
                        },
                        table_id: LookupTable::ResetLookup,
                        value: vec![
                            self.keccak_state.pi_rho_dense_e[i].clone(),
                            self.keccak_state.pi_rho_shifts_e[i].clone(),
                        ],
                    });
                    // Check PiRhoExpandRotE is the expansion of PiRhoDenseRotE
                    self.add_lookup(Lookup {
                        numerator: Signed {
                            sign: Sign::Neg,
                            magnitude: Self::Variable::one(),
                        },
                        table_id: LookupTable::ResetLookup,
                        value: vec![
                            self.keccak_state.pi_rho_dense_rot_e[i].clone(),
                            self.keccak_state.pi_rho_expand_rot_e[i].clone(),
                        ],
                    });
                    // Check that PiRhoRemainderE < 2^64 and PiRhoQuotientE < 2^64
                    self.add_lookup(Lookup {
                        numerator: Signed {
                            sign: Sign::Neg,
                            magnitude: Self::Variable::one(),
                        },
                        table_id: LookupTable::RangeCheck16Lookup,
                        value: vec![self.keccak_state.pi_rho_remainder_e[i].clone()],
                    });
                    self.add_lookup(Lookup {
                        numerator: Signed {
                            sign: Sign::Neg,
                            magnitude: Self::Variable::one(),
                        },
                        table_id: LookupTable::RangeCheck16Lookup,
                        value: vec![self.keccak_state.pi_rho_quotient_e[i].clone()],
                    });
                }
                // Check that the rest of PiRhoShiftsE are in the Sparse table
                for i in 100..SHIFTS_LEN {
                    self.add_lookup(Lookup {
                        numerator: Signed {
                            sign: Sign::Neg,
                            magnitude: Self::Variable::one(),
                        },
                        table_id: LookupTable::SparseLookup,
                        value: vec![self.keccak_state.pi_rho_shifts_e[i].clone()],
                    });
                }
            }
            // CHI LOOKUPS
            {
                // Check ChiShiftsB and ChiShiftsSum are in the Sparse table
                for i in 0..SHIFTS_LEN {
                    self.add_lookup(Lookup {
                        numerator: Signed {
                            sign: Sign::Neg,
                            magnitude: Self::Variable::one(),
                        },
                        table_id: LookupTable::SparseLookup,
                        value: vec![self.keccak_state.chi_shifts_b[i].clone()],
                    });
                    self.add_lookup(Lookup {
                        numerator: Signed {
                            sign: Sign::Neg,
                            magnitude: Self::Variable::one(),
                        },
                        table_id: LookupTable::SparseLookup,
                        value: vec![self.keccak_state.chi_shifts_sum[i].clone()],
                    });
                }
            }
            // IOTA LOOKUPS
            {
                // Check round constants correspond with the current round
                for i in 0..QUARTERS {
                    self.add_lookup(Lookup {
                        numerator: Signed {
                            sign: Sign::Neg,
                            magnitude: Self::Variable::one(),
                        },
                        table_id: LookupTable::RoundConstantsLookup,
                        value: vec![self.round(), self.keccak_state.round_constants[i].clone()],
                    });
                }
            }
        }
    }
}
