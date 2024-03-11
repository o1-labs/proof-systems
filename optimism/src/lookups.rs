//! Instantiation of the lookups for the VM project.

use crate::{keccak::pad_blocks, ramlookup::RAMLookup};
use ark_ff::Field;
use kimchi::{
    circuits::polynomials::keccak::{
        constants::{RATE_IN_BYTES, ROUNDS},
        Keccak, RC,
    },
    o1_utils::Two,
};
use kimchi_msm::{LookupTableID, MVLookupTable};

pub(crate) const TWO_TO_16_UPPERBOUND: u32 = 1 << 16;

/// All of the possible lookup table IDs used in the zkVM
#[derive(Copy, Clone, Debug)]
pub enum LookupTableIDs {
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

impl LookupTableID for LookupTableIDs {
    fn into_field<F: Field>(self) -> F {
        F::from(self as u32)
    }
}

/// The lookups struct based on RAMLookups for the VM table IDs
pub(crate) type Lookup<F> = RAMLookup<F, LookupTableIDs>;

/// The lookup table struct based on MVLookupTable for the VM table IDs
pub(crate) type LookupTable<F> = MVLookupTable<F, LookupTableIDs>;

/// This trait adds basic methods to deal with lookups inside an environment
pub(crate) trait Lookups {
    type Column;
    type Variable: std::ops::Mul<Self::Variable, Output = Self::Variable>
        + std::ops::Add<Self::Variable, Output = Self::Variable>
        + std::ops::Sub<Self::Variable, Output = Self::Variable>
        + std::ops::Neg<Output = Self::Variable>
        + Clone;

    /// Adds a given Lookup to the environment
    fn add_lookup(&mut self, lookup: Lookup<Self::Variable>);

    /// Adds all lookups of Self to the environment
    fn lookups(&mut self);
}

/// Trait that creates all the fixed lookup tables used in the VM
pub(crate) trait FixedLookupTables<F> {
    fn table_range_check_16() -> LookupTable<F>;
    fn table_sparse() -> LookupTable<F>;
    fn table_reset() -> LookupTable<F>;
    fn table_round_constants() -> LookupTable<F>;
    fn table_pad() -> LookupTable<F>;
    fn table_byte() -> LookupTable<F>;
}

impl<F: Field> FixedLookupTables<F> for LookupTable<F> {
    #[allow(dead_code)]
    fn table_range_check_16() -> Self {
        Self {
            table_id: LookupTableIDs::RangeCheck16Lookup,
            entries: (0..TWO_TO_16_UPPERBOUND)
                .map(|i| vec![F::from(i)])
                .collect(),
        }
    }

    #[allow(dead_code)]
    fn table_sparse() -> Self {
        Self {
            table_id: LookupTableIDs::SparseLookup,
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
            table_id: LookupTableIDs::ResetLookup,
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
            table_id: LookupTableIDs::RoundConstantsLookup,
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
            table_id: LookupTableIDs::PadLookup,
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
            table_id: LookupTableIDs::ByteLookup,
            entries: (0..(1 << 8) as u32).map(|i| vec![F::from(i)]).collect(),
        }
    }
}
