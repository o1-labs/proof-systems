//! Instantiation of the lookups for the VM project.

use crate::{
    keccak::witness::pad_blocks,
    ramlookup::{Lookup, LookupTable},
};
use ark_ff::Field;
use kimchi::{
    circuits::polynomials::keccak::{
        constants::{RATE_IN_BYTES, ROUNDS},
        Keccak, RC,
    },
    o1_utils::Two,
};
use kimchi_msm::MVLookupTableID;

pub(crate) const TWO_TO_16_UPPERBOUND: u32 = 1 << 16;

#[derive(Copy, Clone, Debug)]
pub enum VMLookupTableIDs {
    // RAM Tables
    MemoryLookup = 0,
    RegisterLookup = 1,
    /// Syscalls communication channel
    SyscallLookup = 2,
    /// Input/Output of Keccak steps
    KeccakStepLookup = 3,

    // Read Tables
    /// Single-column table of all values in the range [0, 2^16)
    RangeCheck16Lookup = 4,
    /// Single-column table of 2^16 entries with the sparse representation of all values
    SparseLookup = 5,
    /// Dual-column table of all values in the range [0, 2^16) and their sparse representation
    ResetLookup = 6,
    /// 24-row table with all possible values for round and their round constant in expanded form (in big endian)
    RoundConstantsLookup = 7,
    /// All [1..136] values of possible padding lengths, the value 2^len, and the 5 corresponding pad suffixes with the 10*1 rule
    PadLookup = 8,
    /// All values that can be stored in a byte (amortized table, better than model as RangeCheck16 (x and scaled x)
    ByteLookup = 9,
}

impl MVLookupTableID for VMLookupTableIDs {
    fn into_field<F: Field>(self) -> F {
        F::from(self as u32)
    }
}

pub(crate) type VMLookup<F> = Lookup<F, VMLookupTableIDs>;

pub(crate) type VMLookupTable<F> = LookupTable<F, VMLookupTableIDs>;

/// This trait adds basic methods to deal with lookups inside an environment
pub(crate) trait Lookups {
    type Column;
    type Variable: std::ops::Mul<Self::Variable, Output = Self::Variable>
        + std::ops::Add<Self::Variable, Output = Self::Variable>
        + std::ops::Sub<Self::Variable, Output = Self::Variable>
        + std::ops::Neg<Output = Self::Variable>
        + Clone;
    type Table: MVLookupTableID + Send + Sync + Copy;

    /// Adds a given Lookup to the environment
    fn add_lookup(&mut self, lookup: Lookup<Self::Variable, Self::Table>);

    /// Adds all lookups of Self to the environment
    fn lookups(&mut self);
}

impl<F: Field> VMLookupTable<F> {
    #[allow(dead_code)]
    fn table_range_check_16() -> Self {
        Self {
            table_id: VMLookupTableIDs::RangeCheck16Lookup,
            entries: (0..TWO_TO_16_UPPERBOUND)
                .map(|i| vec![F::from(i)])
                .collect(),
        }
    }

    #[allow(dead_code)]
    fn table_sparse() -> Self {
        Self {
            table_id: VMLookupTableIDs::SparseLookup,
            entries: (0..TWO_TO_16_UPPERBOUND)
                .map(|i| {
                    vec![F::from(
                        u64::from_str_radix(&format!("{:b}", i), 16).unwrap(),
                    )]
                })
                .collect(),
        }
    }

    #[allow(dead_code)]
    fn table_reset() -> Self {
        Self {
            table_id: VMLookupTableIDs::ResetLookup,
            entries: (0..TWO_TO_16_UPPERBOUND)
                .map(|i| {
                    vec![
                        F::from(i),
                        F::from(u64::from_str_radix(&format!("{:b}", i), 16).unwrap()),
                    ]
                })
                .collect(),
        }
    }

    #[allow(dead_code)]
    fn table_round_constants() -> Self {
        Self {
            table_id: VMLookupTableIDs::RoundConstantsLookup,
            entries: (0..=ROUNDS)
                .map(|i| {
                    vec![
                        F::from(i as u32),
                        F::from(Keccak::sparse(RC[i])[3]),
                        F::from(Keccak::sparse(RC[i])[2]),
                        F::from(Keccak::sparse(RC[i])[1]),
                        F::from(Keccak::sparse(RC[i])[0]),
                    ]
                })
                .collect(),
        }
    }

    #[allow(dead_code)]
    fn table_pad() -> Self {
        Self {
            table_id: VMLookupTableIDs::PadLookup,
            entries: (1..=RATE_IN_BYTES)
                .map(|i| {
                    let suffix = pad_blocks(i);
                    vec![
                        F::from(i as u64),
                        F::two_pow(i as u64),
                        suffix[0],
                        suffix[1],
                        suffix[2],
                        suffix[3],
                        suffix[4],
                    ]
                })
                .collect(),
        }
    }

    #[allow(dead_code)]
    fn table_byte() -> Self {
        Self {
            table_id: VMLookupTableIDs::ByteLookup,
            entries: (0..(1 << 8) as u32).map(|i| vec![F::from(i)]).collect(),
        }
    }
}
