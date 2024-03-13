//! Instantiate the MVLookup protocol for the MSM project.

use crate::{
    columns::Column,
    expr::{curr_cell, E},
    mvlookup::{LookupTableID, MVLookup, MVLookupWitness},
};
use ark_ff::{FftField, Field, Zero};
use kimchi::circuits::{
    domains::EvaluationDomains,
    expr::{ChallengeTerm, ConstantExpr, ExprInner},
};
use rand::{seq::SliceRandom, thread_rng, Rng};
use std::iter;

/// Lookup tables used in the MSM project
// TODO: Add more built-in lookup tables
#[derive(Copy, Clone, Debug)]
pub enum LookupTableIDs {
    RangeCheck16,
    /// Custom lookup table
    /// The index of the table is used as the ID, padded with the number of
    /// built-in tables.
    Custom(usize),
}

impl LookupTableID for LookupTableIDs {
    fn to_field<F: Field>(&self) -> F {
        match self {
            LookupTableIDs::RangeCheck16 => F::one(),
            LookupTableIDs::Custom(id) => F::from(*id as u64) + F::one(),
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
        LookupWitness {
            f: vec![f_evals],
            t: t_evals,
            m,
        }
    }
}

/// Compute the following constraint:
/// ```text
///                     lhs
///    |------------------------------------------|
///    |                           denominators   |
///    |                         /--------------\ |
/// column * (\prod_{i = 1}^{N} (\beta + f_{i}(X))) =
/// \sum_{i = 1}^{N} m_{i} * \prod_{j = 1, j \neq i}^{N} (\beta + f_{j}(X))
///    |             |--------------------------------------------------|
///    |                             Inner part of rhs                  |
///    |                                                                |
///    |                                                               /
///     \                                                             /
///      \                                                           /
///       \---------------------------------------------------------/
///                           rhs
/// ```
pub fn combine_lookups<F: Field>(column: Column, lookups: Vec<Lookup<E<F>>>) -> E<F> {
    let joint_combiner = {
        let joint_combiner = ConstantExpr::from(ChallengeTerm::JointCombiner);
        E::Atom(ExprInner::Constant(joint_combiner))
    };
    let beta = {
        let beta = ConstantExpr::from(ChallengeTerm::Beta);
        E::Atom(ExprInner::Constant(beta))
    };

    // Compute (\beta + f_{i}(X)) for each i.
    // Note that f_i(X) = x_{0} + r x_{1} + ... r^{N} x_{N} + r^{N + 1} table_id
    let denominators = lookups
        .iter()
        .map(|x| {
            let combined_value = (x
                .value
                .iter()
                .rev()
                .fold(E::zero(), |acc, y| acc * joint_combiner.clone() + y.clone())
                * joint_combiner.clone())
                + x.table_id.to_constraint();
            beta.clone() + combined_value
        })
        .collect::<Vec<_>>();
    // Compute `column * (\prod_{i = 1}^{N} (\beta + f_{i}(X)))`
    let lhs = denominators
        .iter()
        .fold(curr_cell(column), |acc, x| acc * x.clone());
    let rhs = lookups
        .into_iter()
        .enumerate()
        .map(|(i, x)| {
            denominators.iter().enumerate().fold(
                // Compute individual \sum_{j = 1, j \neq i}^{N} f_{j}(X)
                // This is the inner part of rhs. It multiplies with m_{i}
                x.numerator,
                |acc, (j, y)| {
                    if i == j {
                        acc
                    } else {
                        acc * y.clone()
                    }
                },
            )
        })
        // Individual sums
        .reduce(|x, y| x + y)
        .unwrap_or(E::zero());
    lhs - rhs
}
