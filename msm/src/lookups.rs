//! Instantiate the MVLookup protocol for the MSM project.

use crate::mvlookup::{LookupTableID, MVLookup, MVLookupWitness};
use ark_ff::FftField;
use kimchi::circuits::domains::EvaluationDomains;
use rand::{seq::SliceRandom, thread_rng};

/// Lookup tables used in the MSM project
// TODO: Add more built-in lookup tables
#[derive(Copy, Clone, Debug)]
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
}

/// Additive lookups used in the MSM project based on MVLookup
pub type Lookup<F> = MVLookup<F, LookupTableIDs>;

/// Represents a witness of one instance of the lookup argument of the MSM project
pub type LookupWitness<F> = MVLookupWitness<F, LookupTableIDs>;

// This should be used only for testing purposes.
// It is not only in the test API because it is used at the moment in the
// main.rs. It should be moved to the test API when main.rs is replaced with
// real production code.
impl<F: FftField> LookupWitness<F> {
    /// Generate a random number of correct lookups in the table RangeCheck16
    pub fn random(domain: EvaluationDomains<F>) -> Self {
        let n = domain.d1.size as usize;
        let table_id = LookupTableIDs::Custom(42);
        let mut rng = thread_rng();
        // generate one random table with degree n
        let t_values = (0..n).map(|_| F::rand(&mut rng)).collect::<Vec<_>>();
        let mut f: Vec<_> = (0..6)
            .map(|_| {
                let mut t = t_values.clone();
                t.shuffle(&mut rng);
                t.into_iter()
                    .map(|x| MVLookup {
                        table_id,
                        numerator: F::one(),
                        value: vec![x],
                    })
                    .collect::<Vec<_>>()
            })
            .collect();
        let m = (0..n).map(|_| F::from(6_u32)).collect::<Vec<_>>();
        let t = (0..n)
            .map(|i| {
                let numerator = -F::from(6_u32);
                let value = vec![t_values[i]];
                MVLookup {
                    table_id,
                    numerator,
                    value,
                }
            })
            .collect::<Vec<_>>();
        f.push(t);
        Self { f, m }
    }
}
