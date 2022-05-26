use std::collections::HashMap;

use crate::{
    circuits::{
        expr::{prologue::*, Column, ConstantExpr},
        gate::{CircuitGate, CurrOrNext},
        lookup::lookups::{
            JointLookup, JointLookupSpec, JointLookupValue, LocalPosition, LookupInfo, LookupsUsed,
        },
        wires::COLUMNS,
    },
    error::ProverError,
};
use ark_ff::{FftField, One, Zero};
use ark_poly::{EvaluationDomain, Evaluations, Radix2EvaluationDomain as D};
use o1_utils::adjacent_pairs::AdjacentPairs;
use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use CurrOrNext::{Curr, Next};

use super::runtime_tables::{self, RuntimeTableSpec};

/// Number of constraints produced by the argument.
pub const CONSTRAINTS: u32 = 7;

/// The number of random values to append to columns for zero-knowledge.
pub const ZK_ROWS: usize = 3;

/// Pad with zeroes and then add 3 random elements in the last two
/// rows for zero knowledge.
pub fn zk_patch<R: Rng + ?Sized, F: FftField>(
    mut e: Vec<F>,
    d: D<F>,
    rng: &mut R,
) -> Evaluations<F, D<F>> {
    let n = d.size();
    let k = e.len();
    assert!(k <= n - ZK_ROWS);
    e.extend((0..((n - ZK_ROWS) - k)).map(|_| F::zero()));
    e.extend((0..ZK_ROWS).map(|_| F::rand(rng)));
    Evaluations::<F, D<F>>::from_vec_and_domain(e, d)
}

//~
//~ Because of our ZK-rows, we can't do the trick in the plookup paper of
//~ wrapping around to enforce consistency between the sorted lookup columns.
//~
//~ Instead, we arrange the LookupSorted table into columns in a snake-shape.
//~
//~ Like so,
//~
//~ ```
//~ _   _
//~ | | | | |
//~ | | | | |
//~ |_| |_| |
//~ ```
//~
//~ or, imagining the full sorted array is `[ s0, ..., s8 ]`, like
//~
//~ ```
//~ s0 s4 s4 s8
//~ s1 s3 s5 s7
//~ s2 s2 s6 s6
//~ ```
//~
//~ So the direction ("increasing" or "decreasing" (relative to LookupTable) is
//~
//~ ```
//~ if i % 2 = 0 { Increasing } else { Decreasing }
//~ ```
//~
//~ Then, for each `i < max_lookups_per_row`, if `i % 2 = 0`, we enforce that the
//~ last element of `LookupSorted(i) = last element of LookupSorted(i + 1)`,
//~ and if `i % 2 = 1`, we enforce that
//~ the first element of `LookupSorted(i) = first element of LookupSorted(i + 1)`.
//~

/// Computes the sorted lookup tables required by the lookup argument.
pub fn sorted<F>(
    dummy_lookup_value: F,
    joint_lookup_table_d8: &Evaluations<F, D<F>>,
    d1: D<F>,
    gates: &[CircuitGate<F>],
    witness: &[Vec<F>; COLUMNS],
    joint_combiner: F,
    table_id_combiner: F,
) -> Result<Vec<Vec<F>>, ProverError>
where
    F: FftField,
{
    // We pad the lookups so that it is as if we lookup exactly
    // `max_lookups_per_row` in every row.

    let n = d1.size();
    let mut counts: HashMap<&F, usize> = HashMap::new();

    let lookup_rows = n - ZK_ROWS - 1;
    let lookup_info = LookupInfo::<F>::create();
    let by_row = lookup_info.by_row(gates);
    let max_lookups_per_row = lookup_info.max_per_row;

    for t in joint_lookup_table_d8
        .evals
        .iter()
        .step_by(8)
        .take(lookup_rows)
    {
        // Don't multiply-count duplicate values in the table, or they'll be duplicated for each
        // duplicate!
        // E.g. A value duplicated in the table 3 times would be entered into the sorted array 3
        // times at its first occurrence, then a further 2 times as each duplicate is encountered.
        counts.entry(t).or_insert(1);
    }

    // TODO: shouldn't we make sure that lookup rows is the same as the number of active gates in the circuit as well? danger: What if we have gates that use lookup but are not counted here?
    for (i, row) in by_row
        .iter()
        .enumerate()
        // avoid zk rows
        .take(lookup_rows)
    {
        let spec = row;
        let padding = max_lookups_per_row - spec.len();
        for joint_lookup in spec.iter() {
            let eval = |pos: LocalPosition| -> F {
                let row = match pos.row {
                    Curr => i,
                    Next => i + 1,
                };
                witness[pos.column][row]
            };
            let joint_lookup_evaluation =
                joint_lookup.evaluate(&joint_combiner, &table_id_combiner, &eval);
            match counts.get_mut(&joint_lookup_evaluation) {
                None => return Err(ProverError::ValueNotInTable),
                Some(count) => *count += 1,
            }
        }
        *counts.entry(&dummy_lookup_value).or_insert(0) += padding;
    }

    let sorted = {
        let mut sorted: Vec<Vec<F>> =
            vec![Vec::with_capacity(lookup_rows + 1); max_lookups_per_row + 1];

        let mut i = 0;
        for t in joint_lookup_table_d8
            .evals
            .iter()
            .step_by(8)
            // avoid zk rows
            .take(lookup_rows)
        {
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
                sorted[col].push(*t);
            }
            i += t_count;
        }

        for i in 0..max_lookups_per_row {
            let end_val = sorted[i + 1][0];
            sorted[i].push(end_val);
        }

        // Duplicate the final sorted value, to fix the off-by-one in the last lookup row.
        // This is caused by the snakification: all other sorted columns have the value from the
        // next column added to their end, but the final sorted column has no subsequent column to
        // pull this value from.
        let final_sorted_col = &mut sorted[max_lookups_per_row];
        final_sorted_col.push(final_sorted_col[final_sorted_col.len() - 1]);

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
pub fn aggregation<R, F>(
    dummy_lookup_value: F,
    joint_lookup_table_d8: &Evaluations<F, D<F>>,
    d1: D<F>,
    gates: &[CircuitGate<F>],
    witness: &[Vec<F>; COLUMNS],
    joint_combiner: &F,
    table_id_combiner: &F,
    beta: F,
    gamma: F,
    sorted: &[Evaluations<F, D<F>>],
    rng: &mut R,
) -> Result<Evaluations<F, D<F>>, ProverError>
where
    R: Rng + ?Sized,
    F: FftField,
{
    let n = d1.size();
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

    AdjacentPairs::from(joint_lookup_table_d8.evals.iter().step_by(8))
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
                    acc * (gamma + j.evaluate(joint_combiner, table_id_combiner, &eval))
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

    let res = zk_patch(lookup_aggreg, d1, rng);

    // check that the final evaluation is equal to 1
    if cfg!(debug_assertions) {
        let final_val = res.evals[d1.size() - (ZK_ROWS + 1)];
        if final_val != F::one() {
            panic!("aggregation incorrect: {}", final_val);
        }
    }

    Ok(res)
}

/// Configuration for the lookup constraint.
/// These values are independent of the choice of lookup values.
// TODO: move to lookup::index
#[serde_as]
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct LookupConfiguration<F: FftField> {
    /// The kind of lookups used
    pub lookup_used: LookupsUsed,

    /// The maximum number of lookups per row
    pub max_lookups_per_row: usize,

    /// The maximum number of elements in a vector lookup
    pub max_joint_size: u32,

    /// Optional runtime tables, listed as tuples `(length, id)`.
    pub runtime_tables: Option<Vec<RuntimeTableSpec>>,

    /// The offset of the runtime table within the concatenated table
    pub runtime_table_offset: Option<usize>,

    /// A placeholder value that is known to appear in the lookup table.
    /// This is used to pad the lookups to `max_lookups_per_row` when fewer lookups are used in a
    /// particular row, so that we can treat each row uniformly as having the same number of
    /// lookups.
    #[serde_as(as = "JointLookupValue<o1_utils::serialization::SerdeAs>")]
    pub dummy_lookup: JointLookupValue<F>,
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

    // gamma * (beta + 1)
    let gammabeta1 =
        E::<F>::Constant(ConstantExpr::Gamma * (ConstantExpr::Beta + ConstantExpr::one()));

    // the numerator part in the multiset check of plookup
    let numerator = {
        // to toggle dummy queries when we do not have any lookups in a row
        // (1 minus the sum of the lookup selectors)
        let non_lookup_indicator = {
            let lookup_indicator = lookup_info
                .kinds
                .iter()
                .enumerate()
                .map(|(i, _)| column(Column::LookupKindIndex(i)))
                .fold(E::zero(), |acc: E<F>, x| acc + x);

            E::one() - lookup_indicator
        };

        let joint_combiner = ConstantExpr::JointCombiner;
        let table_id_combiner = joint_combiner
            .clone()
            .pow(configuration.max_joint_size.into());

        // combine the columns of the dummy lookup row
        let dummy_lookup = {
            let expr_dummy: JointLookupValue<ConstantExpr<F>> = JointLookup {
                entry: configuration
                    .dummy_lookup
                    .entry
                    .iter()
                    .map(|x| ConstantExpr::Literal(*x))
                    .collect(),
                table_id: ConstantExpr::Literal(configuration.dummy_lookup.table_id),
            };
            expr_dummy.evaluate(&joint_combiner, &table_id_combiner)
        };

        // pre-compute the padding dummies we can use depending on the number of lookups to the `max_per_row` lookups
        // each value is also multipled with (1 + beta)^max_per_row
        // as we need to multiply the denominator with this eventually
        let dummy_padding: Vec<ConstantExpr<F>> = {
            // v contains the `max_per_row` powers of `beta + dummy` starting with 1
            // v[i] = (gamma + dummy)^i
            let mut dummies = vec![ConstantExpr::one()];
            let dummy = ConstantExpr::Gamma + dummy_lookup;
            for i in 1..(lookup_info.max_per_row + 1) {
                dummies.push(dummies[i - 1].clone() * dummy.clone())
            }

            // TODO: we can just multiply with (1+beta)^max_per_row at the end for any f_term, it feels weird to do it here
            // (1 + beta)^max_per_row
            let beta1_per_row: ConstantExpr<F> =
                (ConstantExpr::one() + ConstantExpr::Beta).pow(lookup_info.max_per_row as u64);

            dummies
                .iter()
                .map(|dummies| dummies.clone() * beta1_per_row.clone())
                .collect()
        };

        // This is set up so that on rows that have lookups, chunk will be equal
        // to the product over all lookups `f` in that row of `gamma + f`
        // and
        // on non-lookup rows, will be equal to 1.
        let f_term = |spec: &Vec<JointLookupSpec<_>>| {
            assert!(spec.len() <= lookup_info.max_per_row);

            // padding is (1+beta)^max_per_rows * (gamma + dummy)^pad
            let padding_len = lookup_info.max_per_row - spec.len();
            let padding = dummy_padding[padding_len].clone();

            // padding * \mul (gamma + combined_witnesses)
            let eval = |pos: LocalPosition| witness(pos.column, pos.row);
            spec.iter()
                .map(|j| {
                    E::Constant(ConstantExpr::Gamma)
                        + j.evaluate(
                            &E::Constant(joint_combiner.clone()),
                            &E::Constant(table_id_combiner.clone()),
                            &eval,
                        )
                })
                .fold(E::Constant(padding), |acc: E<F>, x| acc * x)
        };

        // f part of the numerator
        let f_chunk = {
            let dummy_rows = non_lookup_indicator * f_term(&vec![]);

            lookup_info
                .kinds
                .iter()
                .enumerate()
                .map(|(i, spec)| column(Column::LookupKindIndex(i)) * f_term(spec))
                .fold(dummy_rows, |acc, x| acc + x)
        };

        // t part of the numerator
        let t_chunk = gammabeta1.clone()
            + E::cell(Column::LookupTable, Curr)
            + E::beta() * E::cell(Column::LookupTable, Next);

        // return the numerator
        f_chunk * t_chunk
    };

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

    let sorted_size = lookup_info.max_per_row + 1 /* for the XOR lookup table */;

    let denominator = (0..sorted_size)
        .map(|i| {
            let (s1, s2) = if i % 2 == 0 {
                (Curr, Next)
            } else {
                (Next, Curr)
            };

            // gamma * (beta + 1) + sorted[i](x) + beta * sorted[i](x w)
            // or
            // gamma * (beta + 1) + sorted[i](x w) + beta * sorted[i](x)
            gammabeta1.clone()
                + E::cell(Column::LookupSorted(i), s1)
                + E::beta() * E::cell(Column::LookupSorted(i), s2)
        })
        .fold(E::one(), |acc: E<F>, x| acc * x);

    // L(i) * denominator = L(i-1) * numerator
    let aggreg_equation = E::cell(Column::LookupAggreg, Next) * denominator
        - E::cell(Column::LookupAggreg, Curr) * numerator;

    let num_rows = d1.size();
    let num_lookup_rows = num_rows - ZK_ROWS - 1;

    let mut res = vec![
        // the accumulator except for the last 4 rows
        // (contains the zk-rows and the last value of the accumulator)
        E::VanishesOnLast4Rows * aggreg_equation,
        // the initial value of the accumulator
        E::UnnormalizedLagrangeBasis(0) * (E::cell(Column::LookupAggreg, Curr) - E::one()),
        // Check that the final value of the accumulator is 1
        E::UnnormalizedLagrangeBasis(num_lookup_rows)
            * (E::cell(Column::LookupAggreg, Curr) - E::one()),
    ];

    // checks that the snake is turning correctly
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
    res.extend(compatibility_checks);

    // if we are using runtime tables, we add:
    // $RT(x) (1 - \text{selector}_{RT}(x)) = 0$
    if configuration.runtime_tables.is_some() {
        let rt_constraints = runtime_tables::constraints();
        res.extend(rt_constraints);
    }

    res
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
    joint_combiner: &F,
    table_id_combiner: &F,
    sorted: &[Evaluations<F, D<F>>],
) {
    sorted
        .iter()
        .for_each(|s| assert_eq!(d1.size, s.domain().size));
    let n = d1.size();
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
                joint_lookup.evaluate(joint_combiner, table_id_combiner, &eval);
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
