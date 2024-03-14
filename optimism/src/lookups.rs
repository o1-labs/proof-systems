//! Instantiation of the lookups for the VM project.

use self::LookupTableIDs::*;
use crate::{keccak::pad_blocks, ramlookup::RAMLookup};
use ark_ff::Field;
use kimchi::{
    circuits::polynomials::keccak::{
        constants::{RATE_IN_BYTES, ROUNDS},
        Keccak, RC,
    },
    o1_utils::{FieldHelpers, Two},
};
use kimchi_msm::{LookupTableID, MVLookupTable};

/// All of the possible lookup table IDs used in the zkVM
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum LookupTableIDs {
    // PadLookup ID is 0 because this is the only fixed table whose first entry is not 0.
    // This way, it is guaranteed that the 0 value is not always in the tables after the
    // randomization with the joint combiner is applied.
    /// All [1..136] values of possible padding lengths, the value 2^len, and the 5 corresponding pad suffixes with the 10*1 rule
    PadLookup = 0,
    /// 24-row table with all possible values for round and their round constant in expanded form (in big endian)
    RoundConstantsLookup = 1,
    /// All values that can be stored in a byte (amortized table, better than model as RangeCheck16 (x and scaled x)
    ByteLookup = 2,
    // Read tables come first to allow indexing with the table ID for the multiplicities
    /// Single-column table of all values in the range [0, 2^16)
    RangeCheck16Lookup = 3,
    /// Single-column table of 2^16 entries with the sparse representation of all values
    SparseLookup = 4,
    /// Dual-column table of all values in the range [0, 2^16) and their sparse representation
    ResetLookup = 5,

    // RAM Tables
    MemoryLookup = 6,
    RegisterLookup = 7,
    /// Syscalls communication channel
    SyscallLookup = 8,
    /// Input/Output of Keccak steps
    KeccakStepLookup = 9,
}

impl LookupTableID for LookupTableIDs {
    fn into_field<F: Field>(self) -> F {
        F::from(self as u32)
    }

    fn length(&self) -> usize {
        match self {
            PadLookup => RATE_IN_BYTES,
            RoundConstantsLookup => ROUNDS,
            ByteLookup => 1 << 8,
            RangeCheck16Lookup | SparseLookup | ResetLookup => 1 << 16,
            MemoryLookup | RegisterLookup | SyscallLookup | KeccakStepLookup => {
                panic!("RAM Tables do not have a fixed length")
            }
        }
    }
}

/// The lookups struct based on RAMLookups for the VM table IDs
pub(crate) type Lookup<F> = RAMLookup<F, LookupTableIDs>;

/// The lookup table struct based on MVLookupTable for the VM table IDs
pub(crate) type LookupTable<F> = MVLookupTable<F, LookupTableIDs>;

/// Trait that creates all the fixed lookup tables used in the VM
pub(crate) trait FixedLookupTables<F, ID: LookupTableID> {
    /// Checks whether a value is in a table ID and returns the position if it is or None otherwise.
    fn is_in_table(id: ID, value: Vec<F>) -> Option<usize>;
    /// Returns the pad table
    fn table_pad() -> LookupTable<F>;
    /// Returns the round constants table
    fn table_round_constants() -> LookupTable<F>;
    /// Returns the byte table
    fn table_byte() -> LookupTable<F>;
    /// Returns the range check 16 table
    fn table_range_check_16() -> LookupTable<F>;
    /// Returns the sparse table
    fn table_sparse() -> LookupTable<F>;
    /// Returns the reset table
    fn table_reset() -> LookupTable<F>;
}

impl<F: Field> FixedLookupTables<F, LookupTableIDs> for LookupTable<F> {
    fn is_in_table(id: LookupTableIDs, value: Vec<F>) -> Option<usize> {
        let table = match id {
            RangeCheck16Lookup => Self::table_range_check_16().entries,
            SparseLookup => Self::table_sparse().entries,
            ResetLookup => Self::table_reset().entries,
            RoundConstantsLookup => Self::table_round_constants().entries,
            PadLookup => Self::table_pad().entries,
            ByteLookup => Self::table_byte().entries,
            MemoryLookup | RegisterLookup | SyscallLookup | KeccakStepLookup => return None,
        };
        // In these tables, the first value of the vector is related to the index within the table.
        let idx = value[0]
            .to_bytes()
            .iter()
            .rev()
            .fold(0u64, |acc, &x| acc * 256 + x as u64) as usize;

        match id {
            RoundConstantsLookup | ByteLookup | RangeCheck16Lookup | ResetLookup => {
                if idx < id.length() && table[idx] == value {
                    Some(idx)
                } else {
                    None
                }
            }
            PadLookup => {
                // Because this table starts with entry 1
                if idx - 1 < id.length() && table[idx - 1] == value {
                    Some(idx - 1)
                } else {
                    None
                }
            }
            SparseLookup => {
                let res = u64::from_str_radix(&format!("{:x}", idx), 2);
                let dense = if let Ok(ok) = res {
                    ok as usize
                } else {
                    id.length() // So that it returns None
                };
                if dense < id.length() && table[dense] == value {
                    Some(dense)
                } else {
                    None
                }
            }
            MemoryLookup | RegisterLookup | SyscallLookup | KeccakStepLookup => None,
        }
    }

    fn table_pad() -> Self {
        Self {
            table_id: PadLookup,
            entries: (1..=PadLookup.length())
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

    fn table_round_constants() -> Self {
        Self {
            table_id: RoundConstantsLookup,
            entries: (0..RoundConstantsLookup.length())
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

    fn table_byte() -> Self {
        Self {
            table_id: ByteLookup,
            entries: (0..ByteLookup.length())
                .map(|i| vec![F::from(i as u32)])
                .collect(),
        }
    }

    fn table_range_check_16() -> Self {
        Self {
            table_id: RangeCheck16Lookup,
            entries: (0..RangeCheck16Lookup.length())
                .map(|i| vec![F::from(i as u32)])
                .collect(),
        }
    }

    fn table_sparse() -> Self {
        Self {
            table_id: SparseLookup,
            entries: (0..SparseLookup.length())
                .map(|i| {
                    vec![F::from(
                        u64::from_str_radix(&format!("{:b}", i), 16).unwrap(),
                    )]
                })
                .collect(),
        }
    }

    fn table_reset() -> Self {
        Self {
            table_id: ResetLookup,
            entries: (0..ResetLookup.length())
                .map(|i| {
                    vec![
                        F::from(i as u32),
                        F::from(u64::from_str_radix(&format!("{:b}", i), 16).unwrap()),
                    ]
                })
                .collect(),
        }
    }
}
