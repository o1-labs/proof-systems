//! Instantiate the Logup protocol for the MSM project.

use crate::logup::{Logup, LogupWitness, LookupTableID};
use ark_ff::{FftField, PrimeField};
use kimchi::circuits::domains::EvaluationDomains;
use rand::{seq::SliceRandom, thread_rng, Rng};
use std::cmp::Ord;

/// Dummy lookup table. For the cases when you don't need one -- a single dummy element 0.
#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub enum DummyLookupTable {
    DummyLookupTable,
}

impl LookupTableID for DummyLookupTable {
    fn to_u32(&self) -> u32 {
        1
    }

    fn from_u32(id: u32) -> Self {
        match id {
            1 => DummyLookupTable::DummyLookupTable,
            _ => panic!("Dummy lookup table has only index 1"),
        }
    }

    fn length(&self) -> usize {
        1
    }

    /// All tables are fixed tables.
    fn is_fixed(&self) -> bool {
        true
    }

    fn runtime_create_column(&self) -> bool {
        panic!("No runtime tables specified");
    }

    fn ix_by_value<F: PrimeField>(&self, value: &[F]) -> Option<usize> {
        if value[0] == F::zero() {
            Some(0)
        } else {
            panic!("Invalid value for DummyLookupTable")
        }
    }

    fn all_variants() -> Vec<Self> {
        vec![DummyLookupTable::DummyLookupTable]
    }
}

impl DummyLookupTable {
    /// Provides a full list of entries for the given table.
    pub fn entries<F: PrimeField>(&self, domain_d1_size: u64) -> Vec<F> {
        // All zeroes
        (0..domain_d1_size).map(|_| F::zero()).collect()
    }
}

/// Lookup tables used in the MSM project
// TODO: Add more built-in lookup tables
#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub enum LookupTableIDs {
    RangeCheck16,
    /// Custom lookup table
    /// The index of the table is used as the ID, padded with the number of
    /// built-in tables.
    Custom(u32),
}

impl LookupTableID for LookupTableIDs {
    fn to_u32(&self) -> u32 {
        match self {
            LookupTableIDs::RangeCheck16 => 1_u32,
            LookupTableIDs::Custom(id) => id + 1,
        }
    }

    fn from_u32(id: u32) -> Self {
        match id {
            1 => LookupTableIDs::RangeCheck16,
            _ => LookupTableIDs::Custom(id - 1),
        }
    }

    fn length(&self) -> usize {
        match self {
            LookupTableIDs::RangeCheck16 => 1 << 16,
            LookupTableIDs::Custom(_) => todo!(),
        }
    }

    /// All tables are fixed tables.
    fn is_fixed(&self) -> bool {
        true
    }

    fn runtime_create_column(&self) -> bool {
        panic!("No runtime tables specified");
    }

    fn ix_by_value<F: PrimeField>(&self, _value: &[F]) -> Option<usize> {
        todo!()
    }

    fn all_variants() -> Vec<Self> {
        // TODO in the future this must depend on some associated type
        // that parameterises the lookup table.
        vec![Self::RangeCheck16, Self::Custom(0)]
    }
}

/// Additive lookups used in the MSM project based on Logup
pub type Lookup<F> = Logup<F, LookupTableIDs>;

/// Represents a witness of one instance of the lookup argument of the MSM project
pub type LookupWitness<F> = LogupWitness<F, LookupTableIDs>;

// This should be used only for testing purposes.
// It is not only in the test API because it is used at the moment in the
// main.rs. It should be moved to the test API when main.rs is replaced with
// real production code.
impl<F: FftField> LookupWitness<F> {
    /// Generate a random number of correct lookups in the table RangeCheck16
    pub fn random(domain: EvaluationDomains<F>) -> (LookupTableIDs, Self) {
        let mut rng = thread_rng();
        // TODO: generate more random f
        let table_size: u64 = rng.gen_range(1..domain.d1.size);
        let table_id = rng.gen_range(1..1000);
        // Build a table of value we can look up
        let t: Vec<u64> = {
            // Generate distinct values to avoid to have to handle the
            // normalized multiplicity polynomial
            let mut n: Vec<u64> = (1..(table_size * 100)).collect();
            n.shuffle(&mut rng);
            n[0..table_size as usize].to_vec()
        };
        // permutation argument
        let f = {
            let mut f = t.clone();
            f.shuffle(&mut rng);
            f
        };
        let dummy_value = F::rand(&mut rng);
        let repeated_dummy_value: Vec<F> = {
            let r: Vec<F> =
                std::iter::repeat_n(dummy_value, (domain.d1.size - table_size) as usize).collect();
            r
        };
        let t_evals = {
            let mut table = Vec::with_capacity(domain.d1.size as usize);
            table.extend(t.iter().map(|v| Lookup {
                table_id: LookupTableIDs::Custom(table_id),
                numerator: -F::one(),
                value: vec![F::from(*v)],
            }));
            table.extend(
                repeated_dummy_value
                    .iter()
                    .map(|v| Lookup {
                        table_id: LookupTableIDs::Custom(table_id),
                        numerator: -F::one(),
                        value: vec![*v],
                    })
                    .collect::<Vec<Lookup<F>>>(),
            );
            table
        };
        let f_evals: Vec<Lookup<F>> = {
            let mut table = Vec::with_capacity(domain.d1.size as usize);
            table.extend(f.iter().map(|v| Lookup {
                table_id: LookupTableIDs::Custom(table_id),
                numerator: F::one(),
                value: vec![F::from(*v)],
            }));
            table.extend(
                repeated_dummy_value
                    .iter()
                    .map(|v| Lookup {
                        table_id: LookupTableIDs::Custom(table_id),
                        numerator: F::one(),
                        value: vec![*v],
                    })
                    .collect::<Vec<Lookup<F>>>(),
            );
            table
        };
        let m = (0..domain.d1.size).map(|_| F::one()).collect();
        (
            LookupTableIDs::Custom(table_id),
            LookupWitness {
                f: vec![f_evals, t_evals],
                m: vec![m],
            },
        )
    }
}
