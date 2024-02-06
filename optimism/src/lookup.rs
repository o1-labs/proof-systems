use ark_ff::{Field, One};
use kimchi::{
    circuits::polynomials::keccak::{
        constants::{RATE_IN_BYTES, ROUNDS},
        Keccak, RC,
    },
    curve::KimchiCurve,
    o1_utils::Two,
};
use poly_commitment::{OpenProof, PolyComm};

use crate::keccak::{lookups::KeccakLookupColumns, witness::pad_blocks};

#[derive(Copy, Clone, Debug)]
pub enum Sign {
    Pos,
    Neg,
}

#[derive(Copy, Clone, Debug)]
pub enum LookupMode {
    Read,
    Write,
}

#[derive(Copy, Clone, Debug)]
pub enum LookupTables {
    MemoryLookup = 0,
    RegisterLookup = 1,
    // Single-column table of 2^16 entries with the sparse representation of all values
    SparseLookup = 2,
    // Single-column table of all values in the range [0, 2^16)
    RangeCheck16Lookup = 3,
    // Dual-column table of all values in the range [0, 2^16) and their sparse representation
    ResetLookup = 4,
    // 24-row table with all possible values for round and their round constant in expanded form (in big endian)
    RoundConstantsLookup = 5,
    // All [1..136] values of possible padding lengths, the value 2^len, and the 5 corresponding pad suffixes with the 10*1 rule
    PadLookup = 6,
    // All values that can be stored in a byte (amortized table, better than model as RangeCheck16 (x and scaled x)
    ByteLookup = 7,
    // Input/Output of Keccak steps
    KeccakStepLookup = 8,
    // Syscalls communication channel
    SyscallLookup = 9,
}

#[derive(Clone, Debug)]
pub struct Lookup<T> {
    pub mode: LookupMode,
    /// The number of times that this lookup value should be added to / subtracted from the lookup accumulator.
    pub magnitude: T,
    pub table_id: LookupTables,
    pub value: Vec<T>,
}

impl<F: std::fmt::Display + Field> std::fmt::Display for Lookup<F> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let numerator = match self.mode {
            LookupMode::Read => self.magnitude,
            LookupMode::Write => -self.magnitude,
        };
        write!(
            formatter,
            "numerator: {}\ntable_id: {:?}\nvalue:\n[\n",
            numerator, self.table_id
        )?;
        for value in self.value.iter() {
            writeln!(formatter, "\t{}", value)?;
        }
        write!(formatter, "]")?;
        Ok(())
    }
}

impl<T: One> Lookup<T> {
    /// Reads one value when `if_is_true` is 1.
    pub fn read_if(if_is_true: T, table_id: LookupTables, value: Vec<T>) -> Self {
        Self {
            mode: LookupMode::Read,
            magnitude: if_is_true,
            table_id,
            value,
        }
    }

    /// Writes one value when `if_is_true` is 1.
    pub fn write_if(if_is_true: T, table_id: LookupTables, value: Vec<T>) -> Self {
        Self {
            mode: LookupMode::Write,
            magnitude: if_is_true,
            table_id,
            value,
        }
    }

    /// Reads one value from a table.
    pub fn read_one(table_id: LookupTables, value: Vec<T>) -> Self {
        Self {
            mode: LookupMode::Read,
            magnitude: T::one(),
            table_id,
            value,
        }
    }

    /// Writes one value to a table.
    pub fn write_one(table_id: LookupTables, value: Vec<T>) -> Self {
        Self {
            mode: LookupMode::Write,
            magnitude: T::one(),
            table_id,
            value,
        }
    }
}

/// This trait adds basic methods to deal with lookups inside an environment
pub trait Lookups {
    type Column;
    type Variable: std::ops::Mul<Self::Variable, Output = Self::Variable>
        + std::ops::Add<Self::Variable, Output = Self::Variable>
        + std::ops::Sub<Self::Variable, Output = Self::Variable>
        + Clone;

    /// Adds a given Lookup to the environment
    fn add_lookup(&mut self, lookup: Lookup<Self::Variable>);

    /// Adds all lookups of Self to the environment
    fn lookups(&mut self);
}

/// A table of values that can be used for a lookup, along with the ID for the table.
#[derive(Debug, Clone)]
pub struct LookupTable<F> {
    /// The table is a vector of write lookups with the same table ID
    _table: Vec<Lookup<F>>,
}

pub(crate) const TWO_TO_16_UPPERBOUND: u32 = 1 << 16;

impl<F: Field> LookupTable<F> {
    fn _table_range_check_16() -> Self {
        Self {
            _table: (0..TWO_TO_16_UPPERBOUND)
                .map(|i| Lookup {
                    mode: LookupMode::Write,
                    magnitude: F::one(),
                    table_id: LookupTables::RangeCheck16Lookup,
                    value: vec![F::from(i)],
                })
                .collect(),
        }
    }

    fn _table_byte() -> Self {
        Self {
            _table: (0..(1 << 8) as u32)
                .map(|i| Lookup {
                    mode: LookupMode::Write,
                    magnitude: F::one(),
                    table_id: LookupTables::ByteLookup,
                    value: vec![F::from(i)],
                })
                .collect(),
        }
    }

    fn _table_sparse() -> Self {
        Self {
            _table: (0..TWO_TO_16_UPPERBOUND)
                .map(|i| Lookup {
                    mode: LookupMode::Write,
                    magnitude: F::one(),
                    table_id: LookupTables::SparseLookup,
                    value: vec![F::from(
                        u64::from_str_radix(&format!("{:b}", i), 16).unwrap(),
                    )],
                })
                .collect(),
        }
    }

    fn _table_reset() -> Self {
        Self {
            _table: (0..TWO_TO_16_UPPERBOUND)
                .map(|i| Lookup {
                    mode: LookupMode::Write,
                    magnitude: F::one(),
                    table_id: LookupTables::ResetLookup,
                    value: vec![
                        F::from(i),
                        F::from(u64::from_str_radix(&format!("{:b}", i), 16).unwrap()),
                    ],
                })
                .collect(),
        }
    }

    fn _table_round_constants() -> Self {
        Self {
            _table: (0..ROUNDS)
                .map(|i| Lookup {
                    mode: LookupMode::Write,
                    magnitude: F::one(),
                    table_id: LookupTables::RoundConstantsLookup,
                    value: vec![
                        F::from(i as u32),
                        F::from(Keccak::sparse(RC[i])[3]),
                        F::from(Keccak::sparse(RC[i])[2]),
                        F::from(Keccak::sparse(RC[i])[1]),
                        F::from(Keccak::sparse(RC[i])[0]),
                    ],
                })
                .collect(),
        }
    }

    fn _table_pad() -> Self {
        Self {
            _table: (1..=RATE_IN_BYTES)
                .map(|i| {
                    let suffix = pad_blocks(i);
                    Lookup {
                        mode: LookupMode::Write,
                        magnitude: F::one(),
                        table_id: LookupTables::PadLookup,
                        value: vec![
                            F::from(i as u64),
                            F::two_pow(i as u64),
                            suffix[0],
                            suffix[1],
                            suffix[2],
                            suffix[3],
                            suffix[4],
                        ],
                    }
                })
                .collect(),
        }
    }
}

/// Represents the proof of the MV lookup argument
/// It is parametrized by the type `T` which can be either:
/// - Polycomm<G: KimchiCurve> for the commitments
/// - (F, F) for the evaluations at zeta and zeta omega.
#[derive(Debug)]
pub struct MVLookupProof<T> {
    /// Multiplicities of each table entry.
    #[allow(dead_code)]
    pub(crate) multiplicities: Vec<T>,
    /// Each table entry.
    #[allow(dead_code)]
    pub(crate) table_entries: Vec<T>,
    /// All lookup requests per row.
    #[allow(dead_code)]
    pub(crate) lookup_requests: Vec<T>,
    /// Selectors of each lookup per row.
    #[allow(dead_code)]
    pub(crate) selectors: Vec<T>,
    /// Accumulated sum of both sides of the equations of sums.
    #[allow(dead_code)]
    pub(crate) sum: T,
}

/// Represents a proof of the system
/// It is parametrized by the type `T` which can be either:
/// - Polycomm<G: KimchiCurve> for the commitments
/// - (F, F) for the evaluations at zeta and zeta omega.
#[derive(Debug)]
pub struct LookupProof<G: KimchiCurve> {
    /// Polynomial commitments to the witness columns
    pub lookup_commitments: MVLookupProof<PolyComm<G>>,
    /// Evaluations of witness polynomials at current rows on random evaluation point `zeta`
    pub lookup_zeta_evaluations: MVLookupProof<G::ScalarField>,
    /// Evaluations of witness polynomials at next rows (where `* omega` comes from) on random evaluation point `zeta`
    pub lookup_zeta_omega_evaluations: MVLookupProof<G::ScalarField>,
}
