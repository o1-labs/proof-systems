//! Implement the protocol MVLookup <https://eprint.iacr.org/2022/1530.pdf>

use std::iter;

use ark_ff::{FftField, Field};
use kimchi::circuits::domains::EvaluationDomains;
use rand::{seq::SliceRandom, thread_rng, Rng};

// TODO: Add more built-in lookup tables
#[derive(Copy, Clone, Debug)]
pub enum LookupTable {
    RangeCheck16,
    /// Custom lookup table
    /// The index of the table is used as the ID, padded with the number of
    /// built-in tables.
    Custom(usize),
}

impl LookupTable {
    /// Assign a unique ID to the lookup tables.
    pub fn into_field<F: Field>(self) -> F {
        match self {
            LookupTable::RangeCheck16 => F::one(),
            LookupTable::Custom(id) => F::from(id as u64) + F::one(),
        }
    }
}

/// Generic structure to represent a (vector) lookup the table with ID
/// `table_id`.
/// The structure represents the individual fraction of the sum described in the
/// MVLookup protocol (for instance Eq. 8).
/// The table ID is added to the random linear combination formed with the
/// values. The combiner for the random linear combination is coined during the
/// proving phase by the prover.
#[derive(Debug, Clone)]
pub struct Lookup<F> {
    #[allow(dead_code)]
    pub(crate) table_id: LookupTable,
    #[allow(dead_code)]
    pub(crate) numerator: F,
    #[allow(dead_code)]
    pub(crate) value: Vec<F>,
}

/// Represents a witness of one instance of the lookup argument
#[derive(Debug)]
pub struct LookupWitness<F> {
    /// A list of functions/looked-up values.
    #[allow(dead_code)]
    pub(crate) f: Vec<Vec<Lookup<F>>>,
    /// The table the lookup is performed on.
    #[allow(dead_code)]
    pub(crate) t: Vec<Lookup<F>>,
    /// The multiplicity polynomial
    #[allow(dead_code)]
    pub(crate) m: Vec<F>,
}

// This should be used only for testing purposes.
// It is not only in the test API because it is used at the moment in the
// main.rs. It should be moved to the test API when main.rs is replaced with
// real production code.
impl<F: FftField> LookupWitness<F> {
    /// Generate a random number of correct lookups in the table RangeCheck16
    pub fn random(domain: EvaluationDomains<F>) -> Self {
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
            let r: Vec<F> = iter::repeat(dummy_value)
                .take((domain.d1.size - table_size) as usize)
                .collect();
            r
        };
        let t_evals = {
            let mut table = Vec::with_capacity(domain.d1.size as usize);
            table.extend(t.iter().map(|v| Lookup {
                table_id: LookupTable::Custom(table_id),
                numerator: -F::one(),
                value: vec![F::from(*v)],
            }));
            table.extend(
                repeated_dummy_value
                    .iter()
                    .map(|v| Lookup {
                        table_id: LookupTable::Custom(table_id),
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
                table_id: LookupTable::Custom(table_id),
                numerator: F::one(),
                value: vec![F::from(*v)],
            }));
            table.extend(
                repeated_dummy_value
                    .iter()
                    .map(|v| Lookup {
                        table_id: LookupTable::Custom(table_id),
                        numerator: F::one(),
                        value: vec![*v],
                    })
                    .collect::<Vec<Lookup<F>>>(),
            );
            table
        };
        let m = (0..domain.d1.size).map(|_| F::one()).collect();
        LookupWitness {
            f: vec![f_evals],
            t: t_evals,
            m,
        }
    }
}

/// Represents the proof of the lookup argument
/// It is parametrized by the type `T` which can be either:
/// - Polycomm<G: KimchiCurve> for the commitments
/// - F for the evaluations at zeta (resp. zeta omega).
#[derive(Debug, Clone)]
pub struct LookupProof<T> {
    #[allow(dead_code)]
    pub(crate) m: T,
    #[allow(dead_code)]
    // Contain t.
    // TODO: split t and f
    pub(crate) f: Vec<T>,
    // pub(crate) t: T,
    #[allow(dead_code)]
    pub(crate) sum: T,
}

/// Iterator implementation to abstract the content of the structure.
/// It can be used to iterate over the commitments (resp. the evaluations)
/// without requiring to have a look at the inner fields.
impl<'lt, G> IntoIterator for &'lt LookupProof<G> {
    type Item = &'lt G;
    type IntoIter = std::vec::IntoIter<&'lt G>;

    fn into_iter(self) -> Self::IntoIter {
        let n = self.f.len();
        let mut iter_contents = Vec::with_capacity(1 + n + 1);
        iter_contents.push(&self.m);
        iter_contents.extend(&self.f);
        iter_contents.push(&self.sum);
        iter_contents.into_iter()
    }
}
