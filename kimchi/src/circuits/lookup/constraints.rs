use crate::{
    circuits::{
        berkeley_columns::{BerkeleyChallengeTerm, Column},
        expr::{prologue::*, ConstantExpr, ConstantTerm, ExprInner, RowOffset},
        gate::{CircuitGate, CurrOrNext},
        lookup::lookups::{
            JointLookup, JointLookupSpec, JointLookupValue, LocalPosition, LookupInfo,
        },
        wires::COLUMNS,
    },
    error::ProverError,
};
use ark_ff::{FftField, One, PrimeField, Zero};
use ark_poly::{EvaluationDomain, Evaluations, Radix2EvaluationDomain as D};
use o1_utils::adjacent_pairs::AdjacentPairs;
use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use std::collections::HashMap;
use CurrOrNext::{Curr, Next};

use super::runtime_tables;

/// Number of constraints produced by the argument.
pub const CONSTRAINTS: u32 = 7;

/// Pad with zeroes and then add 3 random elements in the last two
/// rows for zero knowledge.
///
/// # Panics
///
/// Will panic if `evaluation` and `domain` length do not meet the requirement.
pub fn zk_patch<R: Rng + ?Sized, F: FftField>(
    mut e: Vec<F>,
    d: D<F>,
    zk_rows: usize,
    rng: &mut R,
) -> Evaluations<F, D<F>> {
    let n = d.size();
    let k = e.len();
    let last_non_zk_row = n - zk_rows;
    assert!(k <= last_non_zk_row);
    e.extend((k..last_non_zk_row).map(|_| F::zero()));
    e.extend((0..zk_rows).map(|_| F::rand(rng)));
    Evaluations::<F, D<F>>::from_vec_and_domain(e, d)
}

//~ Because of our ZK-rows, we can't do the trick in the plookup paper of
//~ wrapping around to enforce consistency between the sorted lookup columns.
//~
//~ Instead, we arrange the LookupSorted table into columns in a snake-shape.
//~
//~ Like so,
//~
//~ ```text
//~    _   _
//~ | | | | |
//~ | | | | |
//~ |_| |_| |
//~ ```
//~
//~ or, imagining the full sorted array is `[ s0, ..., s8 ]`, like
//~
//~ ```text
//~ s0 s4 s4 s8
//~ s1 s3 s5 s7
//~ s2 s2 s6 s6
//~ ```
//~
//~ So the direction ("increasing" or "decreasing" (relative to LookupTable) is
//~
//~ ```rs
//~ if i % 2 = 0 { Increasing } else { Decreasing }
//~ ```
//~
//~ Then, for each `i < max_lookups_per_row`, if `i % 2 = 0`, we enforce that the
//~ last element of `LookupSorted(i) = last element of LookupSorted(i + 1)`,
//~ and if `i % 2 = 1`, we enforce that
//~ the first element of `LookupSorted(i) = first element of LookupSorted(i + 1)`.

/// Computes the sorted lookup tables required by the lookup argument.
///
/// # Panics
///
/// Will panic if `value(s)` are missing from the `table`.
#[allow(clippy::too_many_arguments)]
pub fn sorted<F: PrimeField>(
    dummy_lookup_value: F,
    joint_lookup_table_d8: &Evaluations<F, D<F>>,
    d1: D<F>,
    gates: &[CircuitGate<F>],
    witness: &[Vec<F>; COLUMNS],
    joint_combiner: F,
    table_id_combiner: F,
    lookup_info: &LookupInfo,
    zk_rows: usize,
) -> Result<Vec<Vec<F>>, ProverError> {
    // We pad the lookups so that it is as if we lookup exactly
    // `max_lookups_per_row` in every row.

    let n = d1.size();
    let mut counts: HashMap<&F, usize> = HashMap::new();

    let lookup_rows = n - zk_rows - 1;
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
                None => return Err(ProverError::ValueNotInTable(i)),
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
///
/// # Panics
///
/// Will panic if final evaluation is not 1.
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
    lookup_info: &LookupInfo,
    zk_rows: usize,
) -> Result<Evaluations<F, D<F>>, ProverError>
where
    R: Rng + ?Sized,
    F: PrimeField,
{
    let n = d1.size();
    let lookup_rows = n - zk_rows - 1;
    let beta1: F = F::one() + beta;
    let gammabeta1 = gamma * beta1;
    let mut lookup_aggreg = vec![F::one()];

    lookup_aggreg.extend((0..lookup_rows).map(|row| {
        sorted
            .iter()
            .enumerate()
            .map(|(i, s)| {
                // Snake pattern: even chunks of s are direct
                // while the odd ones are reversed
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

    let max_lookups_per_row = lookup_info.max_per_row;

    let complements_with_beta_term = {
        let mut v = vec![F::one()];
        let x = gamma + dummy_lookup_value;
        for i in 1..=max_lookups_per_row {
            v.push(v[i - 1] * x);
        }

        let beta1_per_row = beta1.pow([max_lookups_per_row as u64]);
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

    let res = zk_patch(lookup_aggreg, d1, zk_rows, rng);

    // check that the final evaluation is equal to 1
    if cfg!(debug_assertions) {
        let final_val = res.evals[d1.size() - (zk_rows + 1)];
        if final_val != F::one() {
            panic!("aggregation incorrect: {final_val}");
        }
    }

    Ok(res)
}

/// Configuration for the lookup constraint.
/// These values are independent of the choice of lookup values.
// TODO: move to lookup::index
#[serde_as]
#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(bound = "F: ark_serialize::CanonicalSerialize + ark_serialize::CanonicalDeserialize")]
pub struct LookupConfiguration<F> {
    /// Information about the specific lookups used
    pub lookup_info: LookupInfo,

    /// A placeholder value that is known to appear in the lookup table.
    /// This is used to pad the lookups to `max_lookups_per_row` when fewer lookups are used in a
    /// particular row, so that we can treat each row uniformly as having the same number of
    /// lookups.
    #[serde_as(as = "JointLookupValue<o1_utils::serialization::SerdeAs>")]
    pub dummy_lookup: JointLookupValue<F>,
}

impl<F: Zero> LookupConfiguration<F> {
    pub fn new(lookup_info: LookupInfo) -> LookupConfiguration<F> {
        // For computational efficiency, we choose the dummy lookup value to be all 0s in table 0.
        let dummy_lookup = JointLookup {
            entry: vec![],
            table_id: F::zero(),
        };

        LookupConfiguration {
            lookup_info,
            dummy_lookup,
        }
    }
}

/// Specifies the lookup constraints as expressions.
///
/// # Panics
///
/// Will panic if single `element` length is bigger than `max_per_row` length.
pub fn constraints<F: FftField>(
    configuration: &LookupConfiguration<F>,
    generate_feature_flags: bool,
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
    let lookup_info = &configuration.lookup_info;

    let column = |col: Column| E::cell(col, Curr);

    // gamma * (beta + 1)
    let gammabeta1 = E::<F>::from(
        ConstantExpr::from(BerkeleyChallengeTerm::Gamma)
            * (ConstantExpr::from(BerkeleyChallengeTerm::Beta) + ConstantExpr::one()),
    );

    // the numerator part in the multiset check of plookup
    let numerator = {
        // to toggle dummy queries when we do not have any lookups in a row
        // (1 minus the sum of the lookup selectors)
        let non_lookup_indicator = {
            let lookup_indicator = lookup_info
                .features
                .patterns
                .into_iter()
                .map(|spec| {
                    let mut term = column(Column::LookupKindIndex(spec));
                    if generate_feature_flags {
                        term = E::IfFeature(
                            FeatureFlag::LookupPattern(spec),
                            Box::new(term),
                            Box::new(E::zero()),
                        )
                    }
                    term
                })
                .fold(E::zero(), |acc: E<F>, x| acc + x);

            E::one() - lookup_indicator
        };

        let joint_combiner = E::from(BerkeleyChallengeTerm::JointCombiner);
        let table_id_combiner =
            // Compute `joint_combiner.pow(lookup_info.max_joint_size)`, injecting feature flags if
            // needed.
            (1..lookup_info.max_joint_size).fold(joint_combiner.clone(), |acc, i| {
                let mut new_term = joint_combiner.clone();
                if generate_feature_flags {
                    new_term = E::IfFeature(
                        FeatureFlag::TableWidth((i + 1) as isize),
                        Box::new(new_term),
                        Box::new(E::one()),
                    );
                }
                acc * new_term
            });

        // combine the columns of the dummy lookup row
        let dummy_lookup = {
            let expr_dummy: JointLookupValue<E<F>> = JointLookup {
                entry: configuration
                    .dummy_lookup
                    .entry
                    .iter()
                    .map(|x| ConstantTerm::Literal(*x).into())
                    .collect(),
                table_id: ConstantTerm::Literal(configuration.dummy_lookup.table_id).into(),
            };
            expr_dummy.evaluate(&joint_combiner, &table_id_combiner)
        };

        // (1 + beta)^max_per_row
        let beta1_per_row: E<F> = {
            let beta1 = E::from(ConstantExpr::one() + BerkeleyChallengeTerm::Beta.into());
            // Compute beta1.pow(lookup_info.max_per_row)
            let mut res = beta1.clone();
            for i in 1..lookup_info.max_per_row {
                let mut beta1_used = beta1.clone();
                if generate_feature_flags {
                    beta1_used = E::IfFeature(
                        FeatureFlag::LookupsPerRow((i + 1) as isize),
                        Box::new(beta1_used),
                        Box::new(E::one()),
                    );
                }
                res *= beta1_used;
            }
            res
        };

        // pre-compute the padding dummies we can use depending on the number of lookups to the `max_per_row` lookups
        // each value is also multiplied with (1 + beta)^max_per_row
        // as we need to multiply the denominator with this eventually
        let dummy_padding = |spec_len| {
            let mut res = E::one();
            let dummy: E<_> = E::from(BerkeleyChallengeTerm::Gamma) + dummy_lookup.clone();
            for i in spec_len..lookup_info.max_per_row {
                let mut dummy_used = dummy.clone();
                if generate_feature_flags {
                    dummy_used = E::IfFeature(
                        FeatureFlag::LookupsPerRow((i + 1) as isize),
                        Box::new(dummy_used),
                        Box::new(E::one()),
                    );
                }
                res *= dummy_used;
            }

            // NOTE: We multiply by beta1_per_row here instead of at the end, because the
            // expression framework will fold the constants together rather than multiplying the
            // whole d8-sized polynomial evaluations by multiple constants.
            res * beta1_per_row.clone()
        };

        // This is set up so that on rows that have lookups, chunk will be equal
        // to the product over all lookups `f` in that row of `gamma + f`
        // and
        // on non-lookup rows, will be equal to 1.
        let f_term = |spec: &Vec<JointLookupSpec<_>>| {
            assert!(spec.len() <= lookup_info.max_per_row);

            // padding is (1+beta)^max_per_rows * (gamma + dummy)^pad
            let padding = dummy_padding(spec.len());

            // padding * \mul (gamma + combined_witnesses)
            let eval = |pos: LocalPosition| witness(pos.column, pos.row);
            spec.iter()
                .map(|j| {
                    E::from(BerkeleyChallengeTerm::Gamma)
                        + j.evaluate(&joint_combiner, &table_id_combiner, &eval)
                })
                .fold(padding, |acc: E<F>, x: E<F>| acc * x)
        };

        // f part of the numerator
        let f_chunk = {
            let dummy_rows = non_lookup_indicator * f_term(&vec![]);

            lookup_info
                .features
                .patterns
                .into_iter()
                .map(|spec| {
                    let mut term =
                        column(Column::LookupKindIndex(spec)) * f_term(&spec.lookups::<F>());
                    if generate_feature_flags {
                        term = E::IfFeature(
                            FeatureFlag::LookupPattern(spec),
                            Box::new(term),
                            Box::new(E::zero()),
                        )
                    }
                    term
                })
                .fold(dummy_rows, |acc, x| acc + x)
        };

        // t part of the numerator
        let t_chunk = gammabeta1.clone()
            + E::cell(Column::LookupTable, Curr)
            + E::from(BerkeleyChallengeTerm::Beta) * E::cell(Column::LookupTable, Next);

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
            let mut expr = gammabeta1.clone()
                + E::cell(Column::LookupSorted(i), s1)
                + E::from(BerkeleyChallengeTerm::Beta) * E::cell(Column::LookupSorted(i), s2);
            if generate_feature_flags {
                expr = E::IfFeature(
                    FeatureFlag::LookupsPerRow(i as isize),
                    Box::new(expr),
                    Box::new(E::one()),
                );
            }
            expr
        })
        .fold(E::one(), |acc: E<F>, x| acc * x);

    // L(i) * denominator = L(i-1) * numerator
    let aggreg_equation = E::cell(Column::LookupAggreg, Next) * denominator
        - E::cell(Column::LookupAggreg, Curr) * numerator;

    let final_lookup_row = RowOffset {
        zk_rows: true,
        offset: -1,
    };

    let mut res = vec![
        // the accumulator except for the last zk_rows+1 rows
        // (contains the zk-rows and the last value of the accumulator)
        E::Atom(ExprInner::VanishesOnZeroKnowledgeAndPreviousRows) * aggreg_equation,
        // the initial value of the accumulator
        E::Atom(ExprInner::UnnormalizedLagrangeBasis(RowOffset {
            zk_rows: false,
            offset: 0,
        })) * (E::cell(Column::LookupAggreg, Curr) - E::one()),
        // Check that the final value of the accumulator is 1
        E::Atom(ExprInner::UnnormalizedLagrangeBasis(final_lookup_row))
            * (E::cell(Column::LookupAggreg, Curr) - E::one()),
    ];

    // checks that the snake is turning correctly
    let compatibility_checks: Vec<_> = (0..lookup_info.max_per_row)
        .map(|i| {
            let first_or_last = if i % 2 == 0 {
                // Check compatibility of the last elements
                final_lookup_row
            } else {
                // Check compatibility of the first elements
                RowOffset {
                    zk_rows: false,
                    offset: 0,
                }
            };
            let mut expr = E::Atom(ExprInner::UnnormalizedLagrangeBasis(first_or_last))
                * (column(Column::LookupSorted(i)) - column(Column::LookupSorted(i + 1)));
            if generate_feature_flags {
                expr = E::IfFeature(
                    FeatureFlag::LookupsPerRow((i + 1) as isize),
                    Box::new(expr),
                    Box::new(E::zero()),
                )
            }
            expr
        })
        .collect();
    res.extend(compatibility_checks);

    // Padding to make sure that the position of the runtime tables constraints is always
    // consistent.
    res.extend((lookup_info.max_per_row..4).map(|_| E::zero()));

    // if we are using runtime tables, we add:
    // $RT(x) (1 - \text{selector}_{RT}(x)) = 0$
    if configuration.lookup_info.features.uses_runtime_tables {
        let mut rt_constraints = runtime_tables::constraints();
        if generate_feature_flags {
            for term in rt_constraints.iter_mut() {
                // Dummy value, to appease the borrow checker.
                let mut boxed_term = Box::new(constant(F::zero()));
                core::mem::swap(term, &mut *boxed_term);
                *term = E::IfFeature(
                    FeatureFlag::RuntimeLookupTables,
                    boxed_term,
                    Box::new(E::zero()),
                )
            }
        }
        res.extend(rt_constraints);
    }

    res
}

/// Checks that all the lookup constraints are satisfied.
///
/// # Panics
///
/// Will panic if `d1` and `s` domain sizes do not match.
#[allow(clippy::too_many_arguments)]
pub fn verify<F: PrimeField, I: Iterator<Item = F>, TABLE: Fn() -> I>(
    dummy_lookup_value: F,
    lookup_table: TABLE,
    lookup_table_entries: usize,
    d1: D<F>,
    gates: &[CircuitGate<F>],
    witness: &[Vec<F>; COLUMNS],
    joint_combiner: &F,
    table_id_combiner: &F,
    sorted: &[Evaluations<F, D<F>>],
    lookup_info: &LookupInfo,
    zk_rows: usize,
) {
    sorted
        .iter()
        .for_each(|s| assert_eq!(d1.size, s.domain().size));
    let n = d1.size();
    let lookup_rows = n - zk_rows - 1;

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
            sorted_joined.extend(es);
        } else {
            sorted_joined.extend(es.rev());
        }
    }

    let mut s_index = 0;
    for t in lookup_table().take(lookup_table_entries) {
        while s_index < sorted_joined.len() && sorted_joined[s_index] == t {
            s_index += 1;
        }
    }
    assert_eq!(s_index, sorted_joined.len());

    let by_row = lookup_info.by_row(gates);

    // Compute lookups||table and check multiset equality
    let sorted_counts: HashMap<F, usize> = {
        let mut counts = HashMap::new();
        for (i, s) in sorted.iter().enumerate() {
            if i % 2 == 0 {
                for x in s.evals.iter().take(lookup_rows) {
                    *counts.entry(*x).or_insert(0) += 1;
                }
            } else {
                for x in s.evals.iter().skip(1).take(lookup_rows) {
                    *counts.entry(*x).or_insert(0) += 1;
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
            *all_lookups.entry(joint_lookup_evaluation).or_insert(0) += 1;
        }

        *all_lookups.entry(dummy_lookup_value).or_insert(0) += lookup_info.max_per_row - spec.len();
    }

    assert_eq!(
        all_lookups.iter().fold(0, |acc, (_, v)| acc + v),
        sorted_counts.iter().fold(0, |acc, (_, v)| acc + v)
    );

    for (k, v) in &all_lookups {
        let s = sorted_counts.get(k).unwrap_or(&0);
        if v != s {
            panic!("For {k}:\nall_lookups    = {v}\nsorted_lookups = {s}");
        }
    }
    for (k, s) in &sorted_counts {
        let v = all_lookups.get(k).unwrap_or(&0);
        if v != s {
            panic!("For {k}:\nall_lookups    = {v}\nsorted_lookups = {s}");
        }
    }
}
