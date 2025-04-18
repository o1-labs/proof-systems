//! Instantiation of the lookups for the VM project.

use self::LookupTableIDs::*;
use crate::{interpreters::keccak::pad_blocks, ramlookup::RAMLookup};
use ark_ff::{Field, PrimeField};
use kimchi::{
    circuits::polynomials::keccak::{
        constants::{RATE_IN_BYTES, ROUNDS},
        Keccak, RC,
    },
    o1_utils::{FieldHelpers, Two},
};
use kimchi_msm::{LogupTable, LogupWitness, LookupTableID};

/// The lookups struct based on RAMLookups for the VM table IDs
pub(crate) type Lookup<F> = RAMLookup<F, LookupTableIDs>;

#[allow(dead_code)]
/// Represents a witness of one instance of the lookup argument of the zkVM project
pub(crate) type LookupWitness<F> = LogupWitness<F, LookupTableIDs>;

/// The lookup table struct based on LogupTable for the VM table IDs
pub(crate) type LookupTable<F> = LogupTable<F, LookupTableIDs>;

/// All of the possible lookup table IDs used in the zkVM
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub enum LookupTableIDs {
    // PadLookup ID is 0 because this is the only fixed table whose first entry
    // is not 0. This way, it is guaranteed that the 0 value is not always in
    // the tables after the randomization with the joint combiner is applied.
    /// All [1..136] values of possible padding lengths, the value 2^len, and
    /// the 5 corresponding pad suffixes with the 10*1 rule
    PadLookup = 0,
    /// 24-row table with all possible values for round and their round constant
    /// in expanded form (in big endian) [0..=23]
    RoundConstantsLookup = 1,
    /// Values from 0 to 4 to check the number of bytes read from syscalls
    AtMost4Lookup = 2,
    /// All values that can be stored in a byte (amortized table, better than
    /// model as RangeCheck16 (x and scaled x)
    ByteLookup = 3,
    // Read tables come first to allow indexing with the table ID for the
    // multiplicities
    /// Single-column table of all values in the range [0, 2^16)
    RangeCheck16Lookup = 4,
    /// Single-column table of 2^16 entries with the sparse representation of
    /// all values
    SparseLookup = 5,
    /// Dual-column table of all values in the range [0, 2^16) and their sparse
    /// representation
    ResetLookup = 6,

    // RAM Tables
    MemoryLookup = 7,
    RegisterLookup = 8,
    /// Syscalls communication channel
    SyscallLookup = 9,
    /// Input/Output of Keccak steps
    KeccakStepLookup = 10,
}

// IMPROVEME: A really should be [A;arity of the table]
#[derive(Clone)]
pub struct FixedLookup<A> {
    pub pad_lookup: A,
    pub round_constants_lookup: A,
    pub at_most_4_lookup: A,
    pub byte_lookup: A,
    pub range_check_16_lookup: A,
    pub sparse_lookup: A,
    pub reset_lookup: A,
}
impl<A> FixedLookup<A> {
    pub fn map<B, F>(self, mut f: F) -> FixedLookup<B>
    where
        F: FnMut(A) -> B,
        Self: Sized,
    {
        let FixedLookup {
            pad_lookup,
            round_constants_lookup,
            at_most_4_lookup,
            byte_lookup,
            range_check_16_lookup,
            sparse_lookup,
            reset_lookup,
        } = self;

        FixedLookup {
            pad_lookup: f(pad_lookup),
            round_constants_lookup: f(round_constants_lookup),
            at_most_4_lookup: f(at_most_4_lookup),
            byte_lookup: f(byte_lookup),
            range_check_16_lookup: f(range_check_16_lookup),
            sparse_lookup: f(sparse_lookup),
            reset_lookup: f(reset_lookup),
        }
    }
}

impl LookupTableID for LookupTableIDs {
    fn to_u32(&self) -> u32 {
        *self as u32
    }

    fn from_u32(value: u32) -> Self {
        match value {
            0 => PadLookup,
            1 => RoundConstantsLookup,
            2 => AtMost4Lookup,
            3 => ByteLookup,
            4 => RangeCheck16Lookup,
            5 => SparseLookup,
            6 => ResetLookup,
            7 => MemoryLookup,
            8 => RegisterLookup,
            9 => SyscallLookup,
            10 => KeccakStepLookup,
            _ => panic!("Invalid table ID"),
        }
    }

    fn length(&self) -> usize {
        match self {
            PadLookup => RATE_IN_BYTES,
            RoundConstantsLookup => ROUNDS,
            AtMost4Lookup => 5,
            ByteLookup => 1 << 8,
            RangeCheck16Lookup | SparseLookup | ResetLookup => 1 << 16,
            MemoryLookup | RegisterLookup | SyscallLookup | KeccakStepLookup => {
                panic!("RAM Tables do not have a fixed length")
            }
        }
    }

    fn is_fixed(&self) -> bool {
        match self {
            PadLookup | RoundConstantsLookup | AtMost4Lookup | ByteLookup | RangeCheck16Lookup
            | SparseLookup | ResetLookup => true,
            MemoryLookup | RegisterLookup | SyscallLookup | KeccakStepLookup => false,
        }
    }

    fn runtime_create_column(&self) -> bool {
        panic!("No runtime tables specified");
    }

    fn ix_by_value<F: PrimeField>(&self, value: &[F]) -> Option<usize> {
        // Shamelessly copied from below, where it is likely also incorrect.
        let idx = value[0]
            .to_bytes()
            .iter()
            .rev()
            .fold(0u64, |acc, &x| acc * 256 + x as u64) as usize;
        match self {
            // Fixed tables
            Self::RoundConstantsLookup
            | Self::AtMost4Lookup
            | Self::ByteLookup
            | Self::RangeCheck16Lookup
            | Self::ResetLookup => Some(idx),
            Self::PadLookup => Some(idx - 1),
            Self::SparseLookup => {
                // Big yikes. This is copied from below.
                let res = u64::from_str_radix(&format!("{:x}", idx), 2);
                if let Ok(ok) = res {
                    Some(ok as usize)
                } else {
                    panic!("Help");
                }
            }
            // Non-fixed tables
            Self::MemoryLookup
            | Self::RegisterLookup
            | Self::SyscallLookup
            | Self::KeccakStepLookup => None,
        }
    }

    fn all_variants() -> Vec<Self> {
        vec![
            Self::PadLookup,
            Self::RoundConstantsLookup,
            Self::AtMost4Lookup,
            Self::ByteLookup,
            Self::RangeCheck16Lookup,
            Self::SparseLookup,
            Self::ResetLookup,
            Self::MemoryLookup,
            Self::RegisterLookup,
            Self::SyscallLookup,
            Self::KeccakStepLookup,
        ]
    }
}

/// Trait that creates all the fixed lookup tables used in the VM
///  Each table can be returned in a 'defauly form with the outer vector
/// indexing the row, and the inner the vector, or the transposed:
/// eg. a range check for n
/// would be [[0],[1],...,[n]]
/// or its transposed version [[0,...,n]]
pub(crate) trait FixedLookupTables<F> {
    /// Checks whether a value is in a table and returns the position if it is
    /// or None otherwise.
    fn is_in_table(table: &LookupTable<F>, value: Vec<F>) -> Option<usize>;

    /// Returns the pad table
    fn table_pad() -> LookupTable<F>;
    fn table_pad_transposed() -> LookupTable<F>;

    /// Returns the round constants table
    fn table_round_constants() -> LookupTable<F>;
    fn table_round_constants_transposed() -> LookupTable<F>;

    /// Returns the at most 4 table
    fn table_at_most_4() -> LookupTable<F>;
    fn table_at_most_4_transposed() -> LookupTable<F>;

    /// Returns the byte table
    fn table_byte() -> LookupTable<F>;
    fn table_byte_transposed() -> LookupTable<F>;

    /// Returns the range check 16 table
    fn table_range_check_16() -> LookupTable<F>;
    fn table_range_check_16_transposed() -> LookupTable<F>;

    /// Returns the sparse table
    fn table_sparse() -> LookupTable<F>;
    fn table_sparse_transposed() -> LookupTable<F>;

    /// Returns the reset table
    fn table_reset() -> LookupTable<F>;
    fn table_reset_transposed() -> LookupTable<F>;

    /// The lookup as given to the lookup prover.
    /// We implement two modifications to the transposed tables:
    /// - We pad with the first element.
    /// - We augment the arity by one, adding the table_id.
    /// eg. the addition for integer smaller than 2 is:
    /// [[0,1,1][0,0,1][0,1,1]] when non formated, and becomes
    /// [[table_id,table_id,table_id,..., table_id][0,1,1, 0...0][0,0,1, 0...0][0,1,1, 0...0]]
    fn get_formated_tables(domain_size: u64) -> FixedLookup<Vec<Vec<F>>>;
}

impl<F: Field + Clone> FixedLookupTables<F> for LookupTable<F> {
    fn get_formated_tables(domain_size: u64) -> FixedLookup<Vec<Vec<F>>> {
        fn format<F: Clone + Field>(lookup_table: LookupTable<F>, domain_size: u64) -> Vec<Vec<F>> {
            let id = vec![lookup_table.table_id.to_field(); domain_size as usize];
            let padded_entries: Vec<Vec<F>> = lookup_table
                .entries
                .into_iter()
                .map(|mut row| {
                    row.extend(vec![row[0]; (domain_size as usize) - row.len()]);
                    row
                })
                .collect();
            let mut id_vec = vec![id];
            id_vec.extend(padded_entries);
            id_vec
        }

        FixedLookup {
            pad_lookup: Self::table_pad_transposed(),
            round_constants_lookup: Self::table_round_constants_transposed(),

            at_most_4_lookup: Self::table_at_most_4_transposed(),
            byte_lookup: Self::table_byte_transposed(),
            range_check_16_lookup: Self::table_range_check_16_transposed(),
            sparse_lookup: Self::table_sparse_transposed(),
            reset_lookup: Self::table_reset_transposed(),
        }
        .map(|table| format(table, domain_size))
    }

    fn is_in_table(table: &LookupTable<F>, value: Vec<F>) -> Option<usize> {
        let id = table.table_id;
        // In these tables, the first value of the vector is related to the
        // index within the table.
        let idx = value[0]
            .to_bytes()
            .iter()
            .rev()
            .fold(0u64, |acc, &x| acc * 256 + x as u64) as usize;

        match id {
            RoundConstantsLookup | AtMost4Lookup | ByteLookup | RangeCheck16Lookup
            | ResetLookup => {
                if idx < id.length() && table.entries[idx] == value {
                    Some(idx)
                } else {
                    None
                }
            }
            PadLookup => {
                // Because this table starts with entry 1
                if idx - 1 < id.length() && table.entries[idx - 1] == value {
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
                if dense < id.length() && table.entries[dense] == value {
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

    fn table_pad_transposed() -> Self {
        let mut entries = vec![vec![]; 7];
        for i in 1..=PadLookup.length() {
            let suffix = pad_blocks(i);
            entries[0].push(F::from(i as u64));
            entries[1].push(F::two_pow(i as u64));
            for j in 0..=4 {
                entries[j + 2].push(suffix[j]);
            }
        }
        Self {
            table_id: PadLookup,
            entries,
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

    // Allow neeless_range_loop to stick closer to 'table_round_constants' code
    #[allow(clippy::needless_range_loop)]
    fn table_round_constants_transposed() -> Self {
        let mut entries = vec![vec![]; 5];
        for i in 0..RoundConstantsLookup.length() {
            entries[0].push(F::from(i as u64));
            for j in 0..=3 {
                entries[j + 1].push(F::from(Keccak::sparse(RC[i])[3 - j]));
            }
        }
        Self {
            table_id: RoundConstantsLookup,
            entries,
        }
    }

    fn table_at_most_4() -> LookupTable<F> {
        Self {
            table_id: AtMost4Lookup,
            entries: (0..AtMost4Lookup.length())
                .map(|i| vec![F::from(i as u32)])
                .collect(),
        }
    }

    fn table_at_most_4_transposed() -> Self {
        let mut entries = vec![vec![]; 1];
        for i in 0..AtMost4Lookup.length() {
            entries[0].push(F::from(i as u32));
        }
        Self {
            table_id: AtMost4Lookup,
            entries,
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

    fn table_byte_transposed() -> Self {
        let mut entries = vec![vec![]; 1];
        for i in 0..ByteLookup.length() {
            entries[0].push(F::from(i as u32));
        }
        Self {
            table_id: ByteLookup,
            entries,
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

    fn table_range_check_16_transposed() -> Self {
        let mut entries = vec![vec![]; 1];
        for i in 0..RangeCheck16Lookup.length() {
            entries[0].push(F::from(i as u32));
        }
        Self {
            table_id: RangeCheck16Lookup,
            entries,
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
    fn table_sparse_transposed() -> Self {
        let mut entries = vec![vec![]; 1];
        for i in 0..SparseLookup.length() {
            entries[0].push(F::from(
                u64::from_str_radix(&format!("{:b}", i), 16).unwrap(),
            ));
        }
        Self {
            table_id: SparseLookup,
            entries,
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
    fn table_reset_transposed() -> Self {
        let mut entries = vec![vec![]; 2];
        for i in 0..ResetLookup.length() {
            entries[0].push(F::from(i as u32));
            entries[1].push(F::from(
                u64::from_str_radix(&format!("{:b}", i), 16).unwrap(),
            ));
        }
        Self {
            table_id: ResetLookup,
            entries,
        }
    }
}
#[test]
fn test_transpose() {
    use ark_ec::AffineRepr;
    use mina_curves::pasta::Vesta;
    let test_one_table =
        |table: LookupTable<<Vesta as AffineRepr>::ScalarField>,
         table_transposed: LookupTable<<Vesta as AffineRepr>::ScalarField>| {
            assert_eq!(table.table_id, table_transposed.table_id);
            for i in 0..table.entries.len() {
                for j in 0..table.entries[0].len() {
                    assert_eq!(table.entries[i][j], table_transposed.entries[j][i])
                }
            }
        };
    test_one_table(
        LookupTable::table_pad(),
        LookupTable::table_pad_transposed(),
    );
    test_one_table(
        LookupTable::table_round_constants(),
        LookupTable::table_round_constants_transposed(),
    );
    test_one_table(
        LookupTable::table_at_most_4(),
        LookupTable::table_at_most_4_transposed(),
    );
    test_one_table(
        LookupTable::table_byte(),
        LookupTable::table_byte_transposed(),
    );
    test_one_table(
        LookupTable::table_range_check_16(),
        LookupTable::table_range_check_16_transposed(),
    );
    test_one_table(
        LookupTable::table_reset(),
        LookupTable::table_reset_transposed(),
    );
    test_one_table(
        LookupTable::table_reset(),
        LookupTable::table_reset_transposed(),
    )
}
