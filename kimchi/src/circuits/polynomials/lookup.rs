//! This source file implements the arithmetization of plookup constraints
//!
//! Because of our ZK-rows, we can't do the trick in the plookup paper of
//! wrapping around to enforce consistency between the sorted lookup columns.
//!
//! Instead, we arrange the LookupSorted table into columns in a snake-shape.
//!
//! Like so,
//! _   _
//! | | | | |
//! | | | | |
//! |_| |_| |
//!
//! or, imagining the full sorted array is [ s0, ..., s8 ], like
//!
//! s0 s4 s4 s8
//! s1 s3 s5 s7
//! s2 s2 s6 s6
//!
//! So the direction ("increasing" or "decreasing" (relative to LookupTable)
//! is
//! if i % 2 = 0 { Increasing } else { Decreasing }
//!
//! Then, for each i < max_lookups_per_row, if i % 2 = 0, we enforce that the
//! last element of LookupSorted(i) = last element of LookupSorted(i + 1),
//! and if i % 2 = 1, we enforce that the
//! first element of LookupSorted(i) = first element of LookupSorted(i + 1)
//!
//! Overview of the protocol
//! ========================
//! * We have our initial table `lookup_table`, with our desired values listed.
//! * We have the implicit table `lookups(witness)` representing the values looked up in each row
//!   of the witness.
//!   - This table is initially variable-width, where some rows have no lookups, and others have
//!     several.
//!   - We explicitly compute this table, and where the width for a particular row is less than the
//!     maximum width, we insert a 'dummy' lookup value as many times as we need to to give every
//!     row the same number of lookups.
//!   - We'll call this padded table `witness_lookups`.
//! * We want to generate a `sorted_table` that contains every entry from the concatenated table
//! `lookup_table||witness_lookups`, where values are in the same order as `lookup_table`, with all
//! duplicates placed next to each other.
//!   - There's an edge case around duplicate values in the `lookup_table` itself: these should
//!     appear in `sorted_table` at least once each time they appeared in the `lookup_table`.
//!   - This ensures that, for any `beta` and for each `i`, the pair `lookup_table[i] + beta *
//!     lookup_table[i+1]` corresponds to some distinct `j` such that `sorted_table[j] + beta *
//!     sorted_table[j+1]`.
//!   - For all other values of `j`, `sorted_table[j] = sorted_table[j+1]`: since we've dealt with
//!     all of the 'different' pairs corresponding from moving from one value in `lookup_table` to
//!     the next, the only remaining pairs are those corresponding to the duplicates provided by the
//!     lookups in `witness_lookups`.
//!   - For example, if `lookup_table` is `[0, 1, 2, 3, 4, 5]` and `witness_lookups` is
//!     `[0, 0, 0, 2, 2, 4]`, then `sorted_table` is `[0, 0, 0, 0, 1, 2, 2, 2, 3, 4, 4, 5]`, and
//!     the differences are
//!     `[(0, 0), (0, 0), (0, 0), (0, 1), (1, 2), (2, 2), (2, 2), (2, 3), (3, 4), (4, 4), (4, 5)]`.
//!     The entries where the pairs are different are those that match with the `lookup_table`, and
//!     the equal pairs can be paired with the `witness_lookups`. This `sorted_table` is computed
//!     by the `sorted` function.
//! * in order to check the multiset inclusion, we calculate the product over our sorted table:
//!   `gamma * (1 + beta) + sorted_table[i] + beta * sorted_table[i+1]`
//!   - again, when the adjacent terms `sorted_table[i]` and `sorted_table[i+1]` are equal, this
//!     simplifies to `(gamma + sorted_table[i]) * (1 + beta)`
//!   - when they are different, there is some `j` such that it equals `gamma * (1 + beta) +
//!     lookup_table[i] + beta * lookup_table[i+1]`
//!   - using the example above, this becomes
//!     ```ignore
//!         gamma * (1 + beta) + 0 + beta * 0
//!       * gamma * (1 + beta) + 0 + beta * 0
//!       * gamma * (1 + beta) + 0 + beta * 0
//!       * gamma * (1 + beta) + 0 + beta * 1
//!       * gamma * (1 + beta) + 1 + beta * 2
//!       * gamma * (1 + beta) + 2 + beta * 2
//!       * gamma * (1 + beta) + 2 + beta * 2
//!       * gamma * (1 + beta) + 2 + beta * 3
//!       * gamma * (1 + beta) + 3 + beta * 4
//!       * gamma * (1 + beta) + 4 + beta * 4
//!       * gamma * (1 + beta) + 4 + beta * 5
//!     ```
//!     which we can simplify to
//!     ```ignore
//!         (gamma + 0) * (1 + beta)
//!       * (gamma + 0) * (1 + beta)
//!       * (gamma + 0) * (1 + beta)
//!       * gamma * (1 + beta) + 0 + beta * 1
//!       * gamma * (1 + beta) + 1 + beta * 2
//!       * (gamma + 2) * (1 + beta)
//!       * (gamma + 2) * (1 + beta)
//!       * gamma * (1 + beta) + 2 + beta * 3
//!       * gamma * (1 + beta) + 3 + beta * 4
//!       * (gamma + 4) * (1 + beta)
//!       * gamma * (1 + beta) + 4 + beta * 5
//!     ```
//! * because we said before that each pair corresponds to either a pair in the `lookup_table` or a
//!   duplicate from the `witness_table`, the product over the sorted table should equal the
//!   product of `gamma * (1 + beta) + lookup_table[i] + beta * lookup_table[i+1]` multiplied by
//!   the product of `(gamma + witness_table[i]) * (1 + beta)`, since each term individually
//!   cancels out.
//!   - using the example above, the `lookup_table` terms become
//!     ```ignore
//!         gamma * (1 + beta) + 0 + beta * 1
//!       * gamma * (1 + beta) + 1 + beta * 2
//!       * gamma * (1 + beta) + 2 + beta * 3
//!       * gamma * (1 + beta) + 3 + beta * 4
//!       * gamma * (1 + beta) + 4 + beta * 5
//!     ```
//!     and the `witness_table` terms become
//!     ```ignore
//!         (gamma + 0) * (1 + beta)
//!       * (gamma + 0) * (1 + beta)
//!       * (gamma + 0) * (1 + beta)
//!       * (gamma + 2) * (1 + beta)
//!       * (gamma + 2) * (1 + beta)
//!       * (gamma + 4) * (1 + beta)
//!     ```
//!
//! There is some nuance around table lengths; for example, notice that `witness_table` need not be
//! the same length as `lookup_table` (and indeed is not in our implementation, due to multiple
//! lookups per row), and that `sorted_table` will always be longer than `lookup_table`, which is
//! where we require 'snakifying' to check consistency. Happily, we don't have to perform
//! snakifying on `witness_table`, because its contribution above only uses a single term rather
//! than a pair of terms.

use crate::{
    circuits::{
        expr::{prologue::*, Column, ConstantExpr, Variable},
        gate::{
            i32_to_field, CircuitGate, CurrOrNext, JointLookup, LocalPosition, LookupInfo,
            LookupTableID, LookupsUsed, SingleLookup,
        },
        wires::COLUMNS,
    },
    error::{ProofError, Result},
};
use ark_ff::{FftField, Field, One, Zero};
use ark_poly::{Evaluations, Radix2EvaluationDomain as D};
use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use std::collections::HashMap;
use CurrOrNext::*;

/// Number of constraints produced by the argument.
pub const CONSTRAINTS: u32 = 7;

// TODO: Update for multiple tables
fn single_lookup<F: FftField>(s: &SingleLookup<F>) -> E<F> {
    // Combine the linear combination.
    s.value
        .iter()
        .map(|(c, pos)| {
            E::literal(*c)
                * E::Cell(Variable {
                    col: Column::Witness(pos.column),
                    row: pos.row,
                })
        })
        .fold(E::zero(), |acc, e| acc + e)
}

fn joint_lookup<F: FftField>(j: &JointLookup<F>, max_joint_size: u32) -> E<F> {
    // The domain-separation term, used to ensure that a lookup against a given table cannot
    // retrieve a value for some other table.
    let table_id_contribution = {
        let table_id = {
            match j.table_id {
                LookupTableID::Constant(table_id) => {
                    let table_id = if table_id >= 0 {
                        F::from(table_id as u32)
                    } else {
                        -F::from(-table_id as u32)
                    };
                    E::constant(ConstantExpr::Literal(table_id))
                }
                LookupTableID::WitnessColumn(col) => {
                    E::cell(Column::Witness(col), CurrOrNext::Curr)
                }
            }
        };
        // Here, we use `joint_combiner^max_joint_size` rather than incrementing the powers of the
        // `joint_combiner` in the table value calculation below. This ensures that we can avoid
        // using higher powers of the `joint_combiner` when we have only one table with a
        // `table_id` of 0.
        E::constant(ConstantExpr::JointCombiner.pow(max_joint_size as u64)) * table_id
    };
    j.entry
        .iter()
        .enumerate()
        .map(|(i, s)| E::constant(ConstantExpr::JointCombiner.pow(i as u64)) * single_lookup(s))
        .fold(E::zero(), |acc, x| acc + x)
        + table_id_contribution
}

struct AdjacentPairs<A, I: Iterator<Item = A>> {
    prev_second_component: Option<A>,
    i: I,
}

impl<A: Copy, I: Iterator<Item = A>> Iterator for AdjacentPairs<A, I> {
    type Item = (A, A);

    fn next(&mut self) -> Option<(A, A)> {
        match self.prev_second_component {
            Some(x) => match self.i.next() {
                None => None,
                Some(y) => {
                    self.prev_second_component = Some(y);
                    Some((x, y))
                }
            },
            None => {
                let x = self.i.next();
                let y = self.i.next();
                match (x, y) {
                    (None, _) | (_, None) => None,
                    (Some(x), Some(y)) => {
                        self.prev_second_component = Some(y);
                        Some((x, y))
                    }
                }
            }
        }
    }
}

fn adjacent_pairs<A: Copy, I: Iterator<Item = A>>(i: I) -> AdjacentPairs<A, I> {
    AdjacentPairs {
        i,
        prev_second_component: None,
    }
}

/// The number of random values to append to columns for zero-knowledge.
pub const ZK_ROWS: usize = 3;

/// Pad with zeroes and then add 3 random elements in the last two
/// rows for zero knowledge.
pub fn zk_patch<R: Rng + ?Sized, F: FftField>(
    mut e: Vec<F>,
    d: D<F>,
    rng: &mut R,
) -> Evaluations<F, D<F>> {
    let n = d.size as usize;
    let k = e.len();
    assert!(k <= n - ZK_ROWS);
    e.extend((0..((n - ZK_ROWS) - k)).map(|_| F::zero()));
    e.extend((0..ZK_ROWS).map(|_| F::rand(rng)));
    Evaluations::<F, D<F>>::from_vec_and_domain(e, d)
}

/// Configuration for the lookup constraint.
/// These values are independent of the choice of lookup values.
#[serde_as]
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct LookupConfiguration<F: FftField> {
    /// The kind of lookups used
    pub lookup_used: LookupsUsed,

    /// The maximum number of lookups per row
    pub max_lookups_per_row: usize,
    /// The maximum number of elements in a vector lookup
    pub max_joint_size: u32,

    #[serde_as(as = "Vec<o1_utils::serialization::SerdeAs>")]
    pub dummy_lookup_value: Vec<F>,
    pub dummy_lookup_table_id: i32,
}

/// Checks that all the lookup constraints are satisfied.
#[allow(clippy::too_many_arguments)]
pub fn verify<F: FftField, I: Iterator<Item = F>, G: Fn() -> I>(
    configuration: &LookupConfiguration<F>,
    dummy_lookup_value: F,
    lookup_table: G,
    lookup_table_entries: usize,
    d1: D<F>,
    gates: &[CircuitGate<F>],
    witness: &[Vec<F>; COLUMNS],
    joint_combiner: F,
    sorted: &[Evaluations<F, D<F>>],
) {
    sorted
        .iter()
        .for_each(|s| assert_eq!(d1.size, s.domain().size));
    let n = d1.size as usize;
    let lookup_rows = n - ZK_ROWS - 1;

    // Check that the (desnakified) sorted table is
    // 1. Sorted
    // 2. Adjacent pairs agree on the final overlap point
    // 3. Multiset-equal to the set lookups||table

    // Check agreement on overlaps
    for i in 0..sorted.len() - 1 {
        let pos = if i % 2 == 0 { lookup_rows } else { 0 };
        assert_eq!(sorted[i][pos], sorted[i + 1][pos]);
    }

    // Check sorting
    let mut sorted_joined: Vec<F> = Vec::with_capacity((lookup_rows + 1) * sorted.len());
    for (i, s) in sorted.iter().enumerate() {
        let es = s.evals.iter().take(lookup_rows + 1);
        if i % 2 == 0 {
            sorted_joined.extend(es)
        } else {
            sorted_joined.extend(es.rev())
        }
    }

    let mut s_index = 0;
    for t in lookup_table().take(lookup_table_entries) {
        while s_index < sorted_joined.len() && sorted_joined[s_index] == t {
            s_index += 1;
        }
    }
    assert_eq!(s_index, sorted_joined.len());

    let lookup_info = LookupInfo::<F>::create();
    let by_row = lookup_info.by_row(gates);

    // Compute lookups||table and check multiset equality
    let sorted_counts: HashMap<F, usize> = {
        let mut counts = HashMap::new();
        for (i, s) in sorted.iter().enumerate() {
            if i % 2 == 0 {
                for x in s.evals.iter().take(lookup_rows) {
                    *counts.entry(*x).or_insert(0) += 1
                }
            } else {
                for x in s.evals.iter().skip(1).take(lookup_rows) {
                    *counts.entry(*x).or_insert(0) += 1
                }
            }
        }
        counts
    };

    let mut all_lookups: HashMap<F, usize> = HashMap::new();
    lookup_table()
        .take(lookup_rows)
        .for_each(|t| *all_lookups.entry(t).or_insert(0) += 1);
    for (i, spec) in by_row.iter().take(lookup_rows).enumerate() {
        let eval = |pos: LocalPosition| -> F {
            let row = match pos.row {
                Curr => i,
                Next => i + 1,
            };
            witness[pos.column][row]
        };
        for joint_lookup in spec.iter() {
            let joint_lookup_evaluation =
                joint_lookup.evaluate(joint_combiner, &eval, configuration.max_joint_size);
            *all_lookups.entry(joint_lookup_evaluation).or_insert(0) += 1
        }

        *all_lookups.entry(dummy_lookup_value).or_insert(0) += lookup_info.max_per_row - spec.len()
    }

    assert_eq!(
        all_lookups.iter().fold(0, |acc, (_, v)| acc + v),
        sorted_counts.iter().fold(0, |acc, (_, v)| acc + v)
    );

    for (k, v) in all_lookups.iter() {
        let s = sorted_counts.get(k).unwrap_or(&0);
        if v != s {
            panic!("For {}:\nall_lookups    = {}\nsorted_lookups = {}", k, v, s);
        }
    }
    for (k, s) in sorted_counts.iter() {
        let v = all_lookups.get(k).unwrap_or(&0);
        if v != s {
            panic!("For {}:\nall_lookups    = {}\nsorted_lookups = {}", k, v, s);
        }
    }
}

pub trait Entry {
    type Field: Field;
    type Params;

    fn evaluate(
        p: &Self::Params,
        j: &JointLookup<Self::Field>,
        witness: &[Vec<Self::Field>; COLUMNS],
        row: usize,
        max_joint_size: u32,
    ) -> Self;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CombinedEntry<F>(pub F);
impl<F: Field> Entry for CombinedEntry<F> {
    type Field = F;
    type Params = F;

    fn evaluate(
        joint_combiner: &F,
        j: &JointLookup<F>,
        witness: &[Vec<F>; COLUMNS],
        row: usize,
        max_joint_size: u32,
    ) -> CombinedEntry<F> {
        let eval = |pos: LocalPosition| -> F {
            let row = match pos.row {
                Curr => row,
                Next => row + 1,
            };
            witness[pos.column][row]
        };

        CombinedEntry(j.evaluate(*joint_combiner, &eval, max_joint_size))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct UncombinedEntry<F>(pub Vec<F>);

impl<F: Field> Entry for UncombinedEntry<F> {
    type Field = F;
    type Params = ();

    fn evaluate(
        _: &(),
        j: &JointLookup<F>,
        witness: &[Vec<F>; COLUMNS],
        row: usize,
        _max_joint_size: u32,
    ) -> UncombinedEntry<F> {
        let eval = |pos: LocalPosition| -> F {
            let row = match pos.row {
                Curr => row,
                Next => row + 1,
            };
            witness[pos.column][row]
        };

        UncombinedEntry(j.entry.iter().map(|s| s.evaluate(&eval)).collect())
    }
}

/// Computes the sorted lookup tables required by the lookup argument.
pub fn sorted<
    F: FftField,
    E: Entry<Field = F> + Eq + std::hash::Hash + Clone,
    I: Iterator<Item = E>,
    G: Fn() -> I,
>(
    configuration: &LookupConfiguration<F>,
    dummy_lookup_value: E,
    lookup_table: G,
    d1: D<F>,
    gates: &[CircuitGate<F>],
    witness: &[Vec<F>; COLUMNS],
    params: E::Params,
) -> Result<Vec<Vec<E>>> {
    // We pad the lookups so that it is as if we lookup exactly
    // `max_lookups_per_row` in every row.

    let n = d1.size as usize;
    let mut counts: HashMap<E, usize> = HashMap::new();

    let lookup_rows = n - ZK_ROWS - 1;
    let lookup_info = LookupInfo::<F>::create();
    let by_row = lookup_info.by_row(gates);
    let max_lookups_per_row = lookup_info.max_per_row;

    for t in lookup_table().take(lookup_rows) {
        // Don't multiply-count duplicate values in the table, or they'll be duplicated for each
        // duplicate!
        // E.g. A value duplicated in the table 3 times would be entered into the sorted array 3
        // times at its first occurrence, then a further 2 times as each duplicate is encountered.
        counts.entry(t).or_insert(1);
    }

    for (i, row) in by_row.iter().enumerate().take(lookup_rows) {
        let spec = row;
        let padding = max_lookups_per_row - spec.len();
        for joint_lookup in spec.iter() {
            let joint_lookup_evaluation = E::evaluate(
                &params,
                joint_lookup,
                witness,
                i,
                configuration.max_joint_size,
            );
            match counts.get_mut(&joint_lookup_evaluation) {
                None => return Err(ProofError::ValueNotInTable),
                Some(count) => *count += 1,
            }
        }
        *counts.entry(dummy_lookup_value.clone()).or_insert(0) += padding;
    }

    let sorted = {
        let mut sorted: Vec<Vec<E>> =
            vec![Vec::with_capacity(lookup_rows + 1); max_lookups_per_row + 1];

        let mut i = 0;
        for t in lookup_table().take(lookup_rows) {
            let t_count = match counts.get_mut(&t) {
                None => panic!("Value has disappeared from count table"),
                Some(x) => {
                    let res = *x;
                    // Reset the count, any duplicate values should only appear once from now on.
                    *x = 1;
                    res
                }
            };
            for j in 0..t_count {
                let idx = i + j;
                let col = idx / lookup_rows;
                sorted[col].push(t.clone());
            }
            i += t_count;
        }

        for i in 0..max_lookups_per_row {
            let end_val = sorted[i + 1][0].clone();
            sorted[i].push(end_val);
        }

        // Duplicate the final sorted value, to fix the off-by-one in the last lookup row.
        // This is caused by the snakification: all other sorted columns have the value from the
        // next column added to their end, but the final sorted column has no subsequent column to
        // pull this value from.
        let final_sorted_col = &mut sorted[max_lookups_per_row];
        final_sorted_col.push(final_sorted_col[final_sorted_col.len() - 1].clone());

        // snake-ify (see top comment)
        for s in sorted.iter_mut().skip(1).step_by(2) {
            s.reverse();
        }

        sorted
    };

    Ok(sorted)
}

/// Computes the aggregation polynomial for maximum n lookups per row, whose kth entry is the product of terms
///
///  (gamma(1 + beta) + t_i + beta t_{i+1}) \prod_{0 <= j < n} ( (1 + beta) (gamma + f_{i,j}) )
/// -------------------------------------------------------------------------------------------
///  \prod_{0 <= j < n+1} (gamma(1 + beta) + s_{i,j} + beta s_{i+1,j})
///
/// for i < k.
///
/// t_i is the ith entry in the table, f_{i, j} is the jth lookup in the ith row of the witness
///
/// for every instance of a value in t_i and f_{i,j}, there is an instance of the same value in s_{i,j}
/// s_{i,j} is sorted in the same order as t_i, increasing along the 'snake-shape'
///
/// whenever the same value is in s_{i,j} and s_{i+1,j}, that term in the denominator product becomes
/// (1 + beta) (gamma + s_{i,j})
/// this will cancel with the corresponding looked-up value in the witness (1 + beta) (gamma + f_{i,j})
///
/// whenever the values s_{i,j} and s_{i+1,j} differ, that term in the denominator product will cancel with some matching
/// (gamma(1 + beta) + t_{i'} + beta t_{i'+1})
/// because the sorting is the same in s and t.
/// there will be exactly the same number of these as the number of values in t if f only contains values from t.
///
/// after multiplying all of the values, all of the terms will have cancelled if s is a sorting of f and t, and the final term will be 1
/// because of the random choice of beta and gamma, there is negligible probability that the terms will cancel if s is not a sorting of f and t
#[allow(clippy::too_many_arguments)]
pub fn aggregation<R: Rng + ?Sized, F: FftField, I: Iterator<Item = F>>(
    configuration: &LookupConfiguration<F>,
    dummy_lookup_value: F,
    lookup_table: I,
    d1: D<F>,
    gates: &[CircuitGate<F>],
    witness: &[Vec<F>; COLUMNS],
    joint_combiner: F,
    beta: F,
    gamma: F,
    sorted: &[Evaluations<F, D<F>>],
    rng: &mut R,
) -> Result<Evaluations<F, D<F>>> {
    let n = d1.size as usize;
    let lookup_rows = n - ZK_ROWS - 1;
    let beta1 = F::one() + beta;
    let gammabeta1 = gamma * beta1;
    let mut lookup_aggreg = vec![F::one()];

    lookup_aggreg.extend((0..lookup_rows).map(|row| {
        sorted
            .iter()
            .enumerate()
            .map(|(i, s)| {
                let (i1, i2) = if i % 2 == 0 {
                    (row, row + 1)
                } else {
                    (row + 1, row)
                };
                gammabeta1 + s[i1] + beta * s[i2]
            })
            .fold(F::one(), |acc, x| acc * x)
    }));
    ark_ff::fields::batch_inversion::<F>(&mut lookup_aggreg[1..]);

    let lookup_info = LookupInfo::<F>::create();
    let max_lookups_per_row = lookup_info.max_per_row;

    let complements_with_beta_term = {
        let mut v = vec![F::one()];
        let x = gamma + dummy_lookup_value;
        for i in 1..(max_lookups_per_row + 1) {
            v.push(v[i - 1] * x)
        }

        let beta1_per_row = beta1.pow(&[max_lookups_per_row as u64]);
        v.iter_mut().for_each(|x| *x *= beta1_per_row);

        v
    };

    adjacent_pairs(lookup_table)
        .take(lookup_rows)
        .zip(lookup_info.by_row(gates))
        .enumerate()
        .for_each(|(i, ((t0, t1), spec))| {
            let f_chunk = {
                let eval = |pos: LocalPosition| -> F {
                    let row = match pos.row {
                        Curr => i,
                        Next => i + 1,
                    };
                    witness[pos.column][row]
                };

                let padding = complements_with_beta_term[max_lookups_per_row - spec.len()];

                // This recomputes `joint_lookup.evaluate` on all the rows, which
                // is also computed in `sorted`. It should pretty cheap relative to
                // the whole cost of the prover, and saves us
                // `max_lookups_per_row (=4) * n` field elements of
                // memory.
                spec.iter().fold(padding, |acc, j| {
                    acc * (gamma + j.evaluate(joint_combiner, &eval, configuration.max_joint_size))
                })
            };

            // At this point, lookup_aggreg[i + 1] contains 1/s_chunk
            // f_chunk / s_chunk
            lookup_aggreg[i + 1] *= f_chunk;
            // f_chunk * t_chunk / s_chunk
            lookup_aggreg[i + 1] *= gammabeta1 + t0 + beta * t1;
            let prev = lookup_aggreg[i];
            // prev * f_chunk * t_chunk / s_chunk
            lookup_aggreg[i + 1] *= prev;
        });

    Ok(zk_patch(lookup_aggreg, d1, rng))
}

/// Specifies the lookup constraints as expressions.
pub fn constraints<F: FftField>(configuration: &LookupConfiguration<F>, d1: D<F>) -> Vec<E<F>> {
    // Something important to keep in mind is that the last 2 rows of
    // all columns will have random values in them to maintain zero-knowledge.
    //
    // Another important thing to note is that there are no lookups permitted
    // in the 3rd to last row.
    //
    // This is because computing the lookup-product requires
    // num_lookup_rows + 1
    // rows, so we need to have
    // num_lookup_rows + 1 = n - 2 (the last 2 being reserved for the zero-knowledge random
    // values) and thus
    //
    // num_lookup_rows = n - 3
    let lookup_info = LookupInfo::<F>::create();

    let column = |col: Column| E::cell(col, Curr);

    let lookup_indicator = lookup_info
        .kinds
        .iter()
        .enumerate()
        .map(|(i, _)| column(Column::LookupKindIndex(i)))
        .fold(E::zero(), |acc: E<F>, x| acc + x);

    let one: E<F> = E::one();
    let non_lookup_indcator = one - lookup_indicator;

    let dummy_table_id_contribution = ConstantExpr::JointCombiner
        .pow(configuration.max_joint_size as u64)
        * ConstantExpr::Literal(i32_to_field(configuration.dummy_lookup_table_id));

    let dummy_lookup: ConstantExpr<F> = configuration
        .dummy_lookup_value
        .iter()
        .rev()
        .fold(ConstantExpr::zero(), |acc, x| {
            ConstantExpr::JointCombiner * acc + ConstantExpr::Literal(*x)
        })
        + dummy_table_id_contribution;

    let complements_with_beta_term: Vec<ConstantExpr<F>> = {
        let mut v = vec![ConstantExpr::one()];
        let x = ConstantExpr::Gamma + dummy_lookup;
        for i in 1..(lookup_info.max_per_row + 1) {
            v.push(v[i - 1].clone() * x.clone())
        }

        let beta1_per_row: ConstantExpr<F> =
            (ConstantExpr::one() + ConstantExpr::Beta).pow(lookup_info.max_per_row as u64);
        v.iter()
            .map(|x| x.clone() * beta1_per_row.clone())
            .collect()
    };

    // This is set up so that on rows that have lookups, chunk will be equal
    // to the product over all lookups `f` in that row of `gamma + f`
    // and
    // on non-lookup rows, will be equal to 1.
    let f_term = |spec: &Vec<_>| {
        assert!(spec.len() <= lookup_info.max_per_row);
        let padding = complements_with_beta_term[lookup_info.max_per_row - spec.len()].clone();

        spec.iter()
            .map(|j| {
                E::Constant(ConstantExpr::Gamma) + joint_lookup(j, configuration.max_joint_size)
            })
            .fold(E::Constant(padding), |acc: E<F>, x| acc * x)
    };
    let f_chunk = lookup_info
        .kinds
        .iter()
        .enumerate()
        .map(|(i, spec)| column(Column::LookupKindIndex(i)) * f_term(spec))
        .fold(non_lookup_indcator * f_term(&vec![]), |acc, x| acc + x);
    let gammabeta1 =
        || E::<F>::Constant(ConstantExpr::Gamma * (ConstantExpr::Beta + ConstantExpr::one()));
    let ft_chunk = f_chunk
        * (gammabeta1()
            + E::cell(Column::LookupTable, Curr)
            + E::beta() * E::cell(Column::LookupTable, Next));

    let num_rows = d1.size as usize;

    let num_lookup_rows = num_rows - ZK_ROWS - 1;

    // Because of our ZK-rows, we can't do the trick in the plookup paper of
    // wrapping around to enforce consistency between the sorted lookup columns.
    //
    // Instead, we arrange the LookupSorted table into columns in a snake-shape.
    //
    // Like so,
    //    _   _
    // | | | | |
    // | | | | |
    // |_| |_| |
    //
    // or, imagining the full sorted array is [ s0, ..., s8 ], like
    //
    // s0 s4 s4 s8
    // s1 s3 s5 s7
    // s2 s2 s6 s6
    //
    // So the direction ("increasing" or "decreasing" (relative to LookupTable)
    // is
    // if i % 2 = 0 { Increasing } else { Decreasing }
    //
    // Then, for each i < max_lookups_per_row, if i % 2 = 0, we enforce that the
    // last element of LookupSorted(i) = last element of LookupSorted(i + 1),
    // and if i % 2 = 1, we enforce that the
    // first element of LookupSorted(i) = first element of LookupSorted(i + 1)

    let s_chunk = (0..(lookup_info.max_per_row + 1))
        .map(|i| {
            let (s1, s2) = if i % 2 == 0 {
                (Curr, Next)
            } else {
                (Next, Curr)
            };

            gammabeta1()
                + E::cell(Column::LookupSorted(i), s1)
                + E::beta() * E::cell(Column::LookupSorted(i), s2)
        })
        .fold(E::one(), |acc: E<F>, x| acc * x);

    let compatibility_checks: Vec<_> = (0..lookup_info.max_per_row)
        .map(|i| {
            let first_or_last = if i % 2 == 0 {
                // Check compatibility of the last elements
                num_lookup_rows
            } else {
                // Check compatibility of the first elements
                0
            };
            E::UnnormalizedLagrangeBasis(first_or_last)
                * (column(Column::LookupSorted(i)) - column(Column::LookupSorted(i + 1)))
        })
        .collect();

    let aggreg_equation = E::cell(Column::LookupAggreg, Next) * s_chunk
        - E::cell(Column::LookupAggreg, Curr) * ft_chunk;

    /*
        aggreg.next =
        aggreg.curr
        * f_chunk
        * (gammabeta1 + index.lookup_tables[0][i] + beta * index.lookup_tables[0][i+1];)
        / (\prod_i (gammabeta1 + lookup_sorted_i.curr + beta * lookup_sorted_i.next))

        rearranging,

        aggreg.next
        * (\prod_i (gammabeta1 + lookup_sorted_i.curr + beta * lookup_sorted_i.next))
        =
        aggreg.curr
        * f_chunk
        * (gammabeta1 + index.lookup_tables[0][i] + beta * index.lookup_tables[0][i+1];)

    */

    let mut res = vec![
        E::VanishesOnLast4Rows * aggreg_equation,
        E::UnnormalizedLagrangeBasis(0) * (E::cell(Column::LookupAggreg, Curr) - E::one()),
        // Check that the 3rd to last row (index = num_rows - 3), which
        // contains the full product, equals 1
        E::UnnormalizedLagrangeBasis(num_lookup_rows)
            * (E::cell(Column::LookupAggreg, Curr) - E::one()),
    ];
    res.extend(compatibility_checks);
    res
}
