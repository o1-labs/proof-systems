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

use ark_poly::{EvaluationDomain, Evaluations, Radix2EvaluationDomain as D};

use crate::expr::{Column, ConstantExpr, Constants, Variable, VariableEvaluator, E};
use crate::{
    gate::{CircuitGate, CurrOrNext, JointLookup, LocalPosition, LookupInfo, SingleLookup},
    wires::COLUMNS,
};
use ark_ff::{FftField, Field, One, Zero};
use oracle::rndoracle::ProofError;
use rand::Rng;
use std::collections::HashMap;
use CurrOrNext::*;

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

fn joint_lookup<F: FftField>(j: &JointLookup<F>, max_joint_size: usize) -> E<F> {
    j.entry
        .iter()
        .enumerate()
        .map(|(i, s)| E::constant(ConstantExpr::JointCombiner.pow(i)) * single_lookup(s))
        .fold(E::zero(), |acc, x| acc + x)
        + E::constant(ConstantExpr::JointCombiner.pow(max_joint_size)) * j.table_id.clone()
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

/// Checks that all the lookup constraints are satisfied.
#[allow(clippy::too_many_arguments)]
pub fn verify<F: FftField, I: Iterator<Item = F>, G: Fn() -> I>(
    dummy_lookup_value: F,
    lookup_table: G,
    lookup_table_entries: usize,
    d1: D<F>,
    gates: &[CircuitGate<F>],
    witness: &[Vec<F>; COLUMNS],
    coefficients8: &[&Vec<F>; COLUMNS],
    joint_combiner: F,
    max_joint_size: usize,
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

    let constants = Constants {
        alpha: F::zero(),
        beta: F::zero(),
        gamma: F::zero(),
        joint_combiner,
        endo_coefficient: F::zero(),
        mds: vec![],
    };
    let evaluator = |row: usize| LookupChunkVariableEvaluator {
        row,
        witness,
        coefficients8,
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
        let evaluators = &[evaluator(i), evaluator(i + 1)];
        let eval_expr = |expr: &E<F>| -> F {
            expr.evaluate_(d1, F::zero(), evaluators, &constants)
                .expect("Lookup evaluation succeeded")
        };
        for joint_lookup in spec.iter() {
            let table_entry =
                joint_lookup.evaluate(joint_combiner, max_joint_size, &eval, &eval_expr);
            *all_lookups.entry(table_entry).or_insert(0) += 1
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

    fn literal(f: Self::Field) -> Self;

    fn evaluate(
        p: &Self::Params,
        max_joint_size: usize,
        j: &JointLookup<Self::Field>,
        witness: &[Vec<Self::Field>; COLUMNS],
        coefficients8: &[&Vec<Self::Field>; COLUMNS],
        row: usize,
    ) -> Self;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CombinedEntry<F>(pub F);
impl<F: FftField> Entry for CombinedEntry<F> {
    type Field = F;
    type Params = F;

    fn literal(f: Self::Field) -> Self {
        CombinedEntry(f)
    }

    fn evaluate(
        joint_combiner: &F,
        max_joint_size: usize,
        j: &JointLookup<F>,
        witness: &[Vec<F>; COLUMNS],
        coefficients8: &[&Vec<F>; COLUMNS],
        row: usize,
    ) -> CombinedEntry<F> {
        let eval = |pos: LocalPosition| -> F {
            let row = match pos.row {
                Curr => row,
                Next => row + 1,
            };
            witness[pos.column][row]
        };
        let constants = Constants {
            alpha: F::zero(),
            beta: F::zero(),
            gamma: F::zero(),
            joint_combiner: *joint_combiner,
            endo_coefficient: F::zero(),
            mds: vec![],
        };
        let evaluator = |row: usize| LookupChunkVariableEvaluator {
            row,
            witness,
            coefficients8,
        };
        let evaluators = &[evaluator(row), evaluator(row + 1)];
        let eval_expr = |expr: &E<F>| -> F {
            expr.evaluate_(
                D::new(0).expect("unitary domain"),
                F::zero(),
                evaluators,
                &constants,
            )
            .expect("Lookup evaluation succeeded")
        };

        CombinedEntry(j.evaluate(*joint_combiner, max_joint_size, &eval, &eval_expr))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct UncombinedEntry<F>(pub Vec<F>);

impl<F: Field> Entry for UncombinedEntry<F> {
    type Field = F;
    type Params = ();

    fn literal(_f: Self::Field) -> Self {
        panic!("TODO");
    }

    fn evaluate(
        _: &(),
        _max_joint_size: usize,
        j: &JointLookup<F>,
        witness: &[Vec<F>; COLUMNS],
        _coefficients8: &[&Vec<F>; COLUMNS],
        row: usize,
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
    E: Entry<Field = F> + Eq + std::hash::Hash + Clone + std::fmt::Debug,
    I: Iterator<Item = E>,
    I2: DoubleEndedIterator<Item = E>,
    G: Fn() -> I,
    G2: Fn() -> I2,
>(
    // TODO: Multiple tables
    dummy_lookup_value: E,
    lookup_table: G,
    lookup_table_entries: usize,
    runtime_table: G2,
    max_joint_size: usize,
    d1: D<F>,
    gates: &[CircuitGate<F>],
    witness: &[Vec<F>; COLUMNS],
    coefficients8: &[&Vec<F>; COLUMNS],
    params: E::Params,
) -> Result<Vec<Vec<E>>, ProofError> {
    // We pad the lookups so that it is as if we lookup exactly
    // `max_lookups_per_row` in every row.

    let n = d1.size as usize;
    let mut counts: HashMap<E, usize> = HashMap::new();

    let lookup_rows = n - ZK_ROWS - 1;
    let lookup_info = LookupInfo::<F>::create();
    let by_row = lookup_info.by_row(gates);
    let max_lookups_per_row = lookup_info.max_per_row;

    for t in runtime_table()
        .take(lookup_rows + 1)
        .chain(lookup_table().take(lookup_rows))
    {
        counts.entry(t).or_insert(1);
    }

    for (i, row) in by_row.iter().enumerate().take(lookup_rows) {
        let spec = row;
        let padding = max_lookups_per_row - spec.len();
        for joint_lookup in spec.iter() {
            let table_entry = E::evaluate(
                &params,
                max_joint_size,
                joint_lookup,
                witness,
                coefficients8,
                i,
            );
            match counts.get_mut(&table_entry) {
                None => return Err(ProofError::ValueNotInTable),
                Some(x) => *x += 1,
            }
        }
        *counts.entry(dummy_lookup_value.clone()).or_insert(0) += padding;
    }

    let sorted = {
        let mut sorted: Vec<Vec<E>> = vec![];
        for _ in 0..max_lookups_per_row + 2 {
            sorted.push(Vec::with_capacity(lookup_rows + 1))
        }

        let mut i = 0;
        // NB: There are lookup_rows+1 different values in the runtime table, all of which
        // participate in the multiset inclusion argument. Thus, we need to consider them all here.
        for t in runtime_table()
            .rev()
            .skip(ZK_ROWS)
            .take(lookup_rows + 1)
            .chain(lookup_table().take(lookup_table_entries))
        {
            let t_count = match counts.get_mut(&t) {
                None => return Err(ProofError::ValueNotInTable),
                Some(x) => {
                    let res = *x;
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

        for i in 0..(max_lookups_per_row + 1) {
            let prev_row = &sorted[i + 1];
            if prev_row.len() > 0 {
                let end_val = prev_row[0].clone();
                sorted[i].push(end_val);
            }
        }

        // Pad columns with zeros
        for i in 0..(max_lookups_per_row + 2) {
            let len = sorted[i].len();
            sorted[i].extend((0..lookup_rows + 1 - len).map(|_| E::literal(F::zero())));
        }

        // snake-ify (see top comment)
        for s in sorted.iter_mut().skip(1).step_by(2) {
            s.reverse();
        }

        sorted
    };

    Ok(sorted)
}

struct LookupChunkVariableEvaluator<'a, F> {
    row: usize,
    witness: &'a [Vec<F>; COLUMNS],
    coefficients8: &'a [&'a Vec<F>; COLUMNS],
}

impl<'a, F: Copy> VariableEvaluator<F> for LookupChunkVariableEvaluator<'a, F> {
    fn witness<'b>(self: &Self, i: usize) -> Result<F, &'b str> {
        Ok(self.witness[i][self.row])
    }
    fn z<'b>(self: &Self) -> Result<F, &'b str> {
        Err("LookupChunkVariableEvaluator z: Not implemented")
    }
    fn lookup_sorted<'b>(self: &Self, _i: usize) -> Result<F, &'b str> {
        Err("LookupChunkVariableEvaluator lookup_sorted: Not implemented")
    }
    fn lookup_aggreg<'b>(self: &Self) -> Result<F, &'b str> {
        Err("LookupChunkVariableEvaluator lookup_aggreg: Not implemented")
    }
    fn lookup_table<'b>(self: &Self) -> Result<F, &'b str> {
        Err("LookupChunkVariableEvaluator lookup_table: Not implemented")
    }
    fn lookup_chunk<'b>(self: &Self) -> Result<F, &'b str> {
        Err("LookupChunkVariableEvaluator lookup_chunk: Not implemented")
    }
    fn runtime_lookup_table<'b>(self: &Self) -> Result<F, &'b str> {
        Err("LookupChunkVariableEvaluator runtime_lookup_table: Not implemented")
    }
    fn index<'b>(self: &Self, _kind: crate::gate::GateType) -> Result<F, &'b str> {
        Err("LookupChunkVariableEvaluator index: Not implemented")
    }
    fn coefficient<'b>(self: &Self, i: usize) -> Result<F, &'b str> {
        Ok(self.coefficients8[i][8 * self.row])
    }
    fn lookup_kind_index<'b>(self: &Self, _i: usize) -> Result<F, &'b str> {
        Err("LookupChunkVariableEvaluator lookup_kind_index: Not implemented")
    }
    fn indexer<'b>(self: &Self) -> Result<F, &'b str> {
        Err("LookupChunkVariableEvaluator indexer: Not implemented")
    }
}

pub fn lookup_chunk<R: Rng + ?Sized, F: FftField>(
    dummy_lookup_value: F,
    d1: D<F>,
    gates: &[CircuitGate<F>],
    witness: &[Vec<F>; COLUMNS],
    coefficients8: &[&Vec<F>; COLUMNS],
    joint_combiner: F,
    max_joint_size: usize,
    beta: F,
    gamma: F,
    rng: &mut R,
) -> Evaluations<F, D<F>> {
    let n = d1.size as usize;
    let lookup_rows = n - ZK_ROWS - 1;

    let lookup_info = LookupInfo::<F>::create();
    let max_lookups_per_row = lookup_info.max_per_row;

    let beta1 = F::one() + beta;

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
    let constants = Constants {
        alpha: F::zero(),
        beta,
        gamma,
        joint_combiner,
        endo_coefficient: F::zero(),
        mds: vec![],
    };
    let evaluator = |row: usize| LookupChunkVariableEvaluator {
        row,
        witness,
        coefficients8,
    };
    let lookup_chunk: Vec<_> = lookup_info
        .by_row(gates)
        .iter()
        .take(lookup_rows)
        .enumerate()
        .map(|(i, spec)| {
            let eval = |pos: LocalPosition| -> F {
                let row = match pos.row {
                    Curr => i,
                    Next => i + 1,
                };
                witness[pos.column][row]
            };
            let evaluators = &[evaluator(i), evaluator(i + 1)];
            let eval_expr = |expr: &E<F>| -> F {
                expr.evaluate_(d1, F::zero(), evaluators, &constants)
                    .expect("Lookup evaluation succeeded")
            };

            let padding = complements_with_beta_term[max_lookups_per_row - spec.len()];

            // This recomputes `joint_lookup.evaluate` on all the rows, which
            // is also computed in `sorted`. It should pretty cheap relative to
            // the whole cost of the prover, and saves us
            // `max_lookups_per_row (=4) * n` field elements of
            // memory.
            spec.iter().fold(padding, |acc, j| {
                let res = j.evaluate(joint_combiner, max_joint_size, &eval, &eval_expr);
                acc * (gamma + res)
            })
        })
        .collect();
    zk_patch(lookup_chunk, d1, rng)
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
pub fn aggregation<R: Rng + ?Sized, F: FftField, I: DoubleEndedIterator<Item = F>>(
    lookup_table: I,
    runtime_table: I,
    lookup_chunk: I,
    d1: D<F>,
    beta: F,
    gamma: F,
    sorted: &[Evaluations<F, D<F>>],
    rng: &mut R,
) -> Result<Evaluations<F, D<F>>, ProofError> {
    let n = d1.size as usize;
    let lookup_rows = n - ZK_ROWS - 1;
    let beta1 = F::one() + beta;
    let gammabeta1 = gamma * beta1;
    // Due to the snaking of the lookup and runtime tables, there's actually 1 more value included
    // in the numerator of the lookup argument vs the denominator. To compensate, we include the
    // value here, abusing the fact that we know the lookup table is padded with 0s.
    // In essence, here we are including the evaluation
    // `gamma * (beta + 1) + x + beta * x`
    // but simplified using x = 0.
    let mut lookup_aggreg = vec![gammabeta1];

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
    ark_ff::fields::batch_inversion::<F>(&mut lookup_aggreg[0..]);

    adjacent_pairs(lookup_table)
        .take(lookup_rows)
        .zip(adjacent_pairs(runtime_table))
        .zip(lookup_chunk)
        .enumerate()
        .for_each(|(i, (((t0, t1), (rt0, rt1)), f_chunk))| {
            if i == 0 {
                // Snakify between lookup_table and runtime_table
                lookup_aggreg[0] *= gammabeta1 + rt0 + beta * t0;
            }

            // At this point, lookup_aggreg[i + 1] contains 1/s_chunk
            // f_chunk / s_chunk
            lookup_aggreg[i + 1] *= f_chunk;
            // f_chunk * t_chunk / s_chunk
            lookup_aggreg[i + 1] *= gammabeta1 + t0 + beta * t1;
            // f_chunk * t_chunk * rt_chunk / s_chunk
            lookup_aggreg[i + 1] *= gammabeta1 + rt1 + beta * rt0;
            let prev = lookup_aggreg[i];
            // prev * f_chunk * t_chunk * rt_chunk / s_chunk
            lookup_aggreg[i + 1] *= prev;
        });

    Ok(zk_patch(lookup_aggreg, d1, rng))
}

/// Specifies the lookup constraints as expressions.
pub fn constraints<F: FftField>(
    dummy_lookup: &[F],
    dummy_lookup_table_id: u32,
    d1: D<F>,
    max_joint_size: usize,
) -> Vec<E<F>> {
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

    let dummy_lookup: ConstantExpr<F> = dummy_lookup
        .iter()
        .rev()
        .fold(ConstantExpr::zero(), |acc, x| {
            ConstantExpr::JointCombiner * acc + ConstantExpr::Literal(*x)
        })
        + (ConstantExpr::JointCombiner.pow(max_joint_size)
            * ConstantExpr::Literal(dummy_lookup_table_id.into()));

    let complements_with_beta_term: Vec<ConstantExpr<F>> = {
        let mut v = vec![ConstantExpr::one()];
        let x = ConstantExpr::Gamma + dummy_lookup;
        for i in 1..(lookup_info.max_per_row + 1) {
            v.push(v[i - 1].clone() * x.clone())
        }

        let beta1_per_row: ConstantExpr<F> =
            (ConstantExpr::one() + ConstantExpr::Beta).pow(lookup_info.max_per_row);
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
            .map(|j| E::Constant(ConstantExpr::Gamma) + joint_lookup(j, max_joint_size))
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
    let ft_chunk = E::cell(Column::LookupChunk, Curr)
        * (gammabeta1()
            + E::cell(Column::LookupTable, Curr)
            + E::beta() * E::cell(Column::LookupTable, Next));

    let runtime_table_entry = |curr_or_next| -> E<F> {
        E::cell(Column::RuntimeLookupTable, curr_or_next) * E::constant(ConstantExpr::JointCombiner)
            + E::cell(Column::Indexer, curr_or_next)
            - E::constant(ConstantExpr::JointCombiner).pow(max_joint_size)
    };

    let rt_chunk = ft_chunk
        * (gammabeta1() + runtime_table_entry(Next) + E::beta() * runtime_table_entry(Curr));

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

    let s_chunk = (0..(lookup_info.max_per_row + 2))
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

    let compatibility_checks: Vec<_> = (0..lookup_info.max_per_row + 1)
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
        - E::cell(Column::LookupAggreg, Curr) * rt_chunk;

    /*
        aggreg.next =
        aggreg.curr
        * f_chunk
        * (gammabeta1 + index.lookup_tables[0][i] + beta * index.lookup_tables[0][i+1])
        * (gammabeta1 + index.runtime_table[i+1] + beta * index.runtime_tables[i])
        / (\prod_i (gammabeta1 + lookup_sorted_i.curr + beta * lookup_sorted_i.next))

        rearranging,

        aggreg.next
        * (\prod_i (gammabeta1 + lookup_sorted_i.curr + beta * lookup_sorted_i.next))
        =
        aggreg.curr
        * f_chunk
        * (gammabeta1 + index.lookup_tables[0][i] + beta * index.lookup_tables[0][i+1])
        * (gammabeta1 + index.runtime_table[i+1] + beta * index.runtime_tables[i])

    */

    let mut res = vec![
        E::VanishesOnLast4Rows * aggreg_equation,
        E::VanishesOnLast4Rows * (E::cell(Column::LookupChunk, Curr) - f_chunk),
        // Check that the first term matches the 'snakification' term for the lookup_table and
        // runtime_table. Without this term, the RHS of lookupaggreg[0] would be 1; we multiply by
        // this term to add continuity between the two tables.
        // Doing this allows us to avoid the compatibility check -- and, more importantly, allows
        // us to avoid massaging the tables so that this check holds.
        //
        // To account for the extra term in the numerator for joining the runtime table to the
        // lookup table, we also introduce a `gamma * (beta + 1) + x + beta * x` term into the
        // denominator for the missing final value `x` in the lookup table. Happily, this value is
        // 0, so we simplify this down to `gamma * (beta + 1)`.
        E::UnnormalizedLagrangeBasis(0)
            * (E::cell(Column::LookupAggreg, Curr) * gammabeta1()
                - gammabeta1()
                - runtime_table_entry(Curr)
                - E::beta() * E::cell(Column::LookupTable, Curr)),
        // Check that the 3rd to last row (index = num_rows - 3), which
        // contains the full product, equals 1
        E::UnnormalizedLagrangeBasis(num_lookup_rows)
            * (E::cell(Column::LookupAggreg, Curr) - E::one()),
    ];
    res.extend(compatibility_checks);
    res
}
