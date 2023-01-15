use crate::{
    circuits::{
        expr::{prologue::*, Column, ConstantExpr},
        gate::{CircuitGate, CurrOrNext::*},
        lookup::{
            constraints::{zk_patch, LookupConfiguration},
            lookups::{JointLookupSpec, LocalPosition, LookupInfo},
            runtime_tables,
        },
        wires::COLUMNS,
    },
    error::ProverError,
};
use ark_ff::{FftField, One, PrimeField, Zero};
use ark_poly::{EvaluationDomain, Evaluations, Radix2EvaluationDomain as D};
use rand::Rng;
use std::collections::HashMap;

pub const ZK_ROWS: usize = 3;

/// Specifies the additive lookup constraints as expressions.
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
    // This is because computing the lookup-aggregation requires
    // num_lookup_rows + 1
    // rows, so we need to have
    // num_lookup_rows + 1 = n - 2 (the last 2 being reserved for the zero-knowledge random
    // values) and thus
    //
    // num_lookup_rows = n - 3
    let lookup_info = &configuration.lookup_info;

    let column = |col: Column| E::cell(col, Curr);

    // The contributions given by each lookup pattern.
    let lookup_contributions = {
        let joint_combiner = E::Constant(ConstantExpr::JointCombiner);
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

        // This is set up so that on rows that have lookups, chunk will be equal
        // to the product over all lookups `f` in that row of `gamma + f`
        // and
        // on non-lookup rows, will be equal to 1.
        let f_term = |spec: &Vec<JointLookupSpec<_>>| {
            assert!(spec.len() <= lookup_info.max_per_row);

            // padding * \mul (gamma + combined_witnesses)
            let eval = |pos: LocalPosition| witness(pos.column, pos.row);
            spec.iter()
                .map(|j| {
                    (E::Constant(ConstantExpr::Beta)
                        + j.evaluate(&joint_combiner, &table_id_combiner, &eval))
                    .inverse()
                })
                .fold(None, |acc: Option<E<F>>, x| match acc {
                    Some(acc) => Some(acc + x),
                    None => Some(x),
                })
        };

        lookup_info
            .features
            .patterns
            .into_iter()
            .filter_map(|spec| {
                let mut term =
                    column(Column::LookupKindIndex(spec)) * f_term(&spec.lookups::<F>())?;
                if generate_feature_flags {
                    term = E::IfFeature(
                        FeatureFlag::LookupPattern(spec),
                        Box::new(term),
                        Box::new(E::zero()),
                    )
                }
                Some(term)
            })
            .fold(None, |acc, x| match acc {
                Some(acc) => Some(acc + x),
                None => Some(x),
            })
    };

    // aggregation[i] = aggregation[i-1] + lookups - table
    // Therefore
    // table = aggregation[i-1] - aggregation[i] + lookups
    let expected_table = {
        let mut res = E::cell(Column::AdditiveLookupAggregation, Curr)
            - E::cell(Column::AdditiveLookupAggregation, Next);
        if let Some(lookup_contributions) = lookup_contributions {
            res += lookup_contributions;
        }
        res
    };

    // table = count / (beta + table_entry)
    // (beta + table_entry) * table = count
    let aggreg_equation = {
        (E::Constant(ConstantExpr::Beta) + E::cell(Column::LookupTable, Curr)) * expected_table
            - E::cell(Column::AdditiveLookupCount, Curr)
    };

    let final_lookup_row: i32 = -(ZK_ROWS as i32) - 1;

    let mut res = vec![
        // the accumulator except for the last 4 rows
        // (contains the zk-rows and the last value of the accumulator)
        E::VanishesOnLast4Rows * aggreg_equation,
        // the initial value of the accumulator
        E::UnnormalizedLagrangeBasis(0)
            * (E::cell(Column::AdditiveLookupAggregation, Curr) - E::zero()),
        // Check that the final value of the accumulator is 1
        E::UnnormalizedLagrangeBasis(final_lookup_row)
            * (E::cell(Column::AdditiveLookupAggregation, Curr) - E::zero()),
    ];

    // if we are using runtime tables, we add:
    // $RT(x) (1 - \text{selector}_{RT}(x)) = 0$
    if configuration.lookup_info.features.uses_runtime_tables {
        let mut rt_constraints = runtime_tables::constraints();
        if generate_feature_flags {
            for term in rt_constraints.iter_mut() {
                // Dummy value, to appease the borrow checker.
                let mut boxed_term = Box::new(constant(F::zero()));
                std::mem::swap(term, &mut *boxed_term);
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

pub struct ComputedColumns<F> {
    pub counts: F,
    pub aggregation: F,
    pub inverses: Vec<F>,
}

/// Compute the aggregation and counts polynomials
#[allow(clippy::too_many_arguments)]
pub fn compute_aggregations<R: Rng + ?Sized, F: PrimeField>(
    joint_lookup_table_d8: &Evaluations<F, D<F>>,
    d1: D<F>,
    gates: &[CircuitGate<F>],
    witness: &[Vec<F>; COLUMNS],
    joint_combiner: F,
    table_id_combiner: F,
    lookup_info: &LookupInfo,
    beta: F,
    rng: &mut R,
) -> Result<ComputedColumns<Evaluations<F, D<F>>>, ProverError> {
    let n = d1.size();
    let lookup_rows = n - ZK_ROWS - 1;

    let mut aggregation = Vec::with_capacity(d1.size());

    aggregation.push(F::zero());

    let mut counts_map = {
        let mut counts: HashMap<F, usize> = HashMap::new();

        let by_row = lookup_info.by_row(gates);

        for (i, row) in by_row
            .iter()
            .enumerate()
            // avoid zk rows
            .take(lookup_rows)
        {
            let spec = row;
            let mut lookup_contributions = F::zero();
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
                *counts.entry(joint_lookup_evaluation).or_insert(0) += 1;
                lookup_contributions += (beta + joint_lookup_evaluation).inverse().ok_or(
                    ProverError::DivisionByZero(
                        "Could not invert one of the joint lookup evaluations",
                    ),
                )?;
            }
            aggregation.push(lookup_contributions)
        }

        counts
    };

    let mut counts = Vec::with_capacity(d1.size());

    for (i, lookup_value) in joint_lookup_table_d8
        .evals
        .iter()
        .step_by(8)
        .take(lookup_rows)
        .enumerate()
    {
        if let Some((_, lookup_count)) = counts_map.remove_entry(lookup_value) {
            let lookup_count = F::from(lookup_count as u64);
            counts.push(lookup_count);
            let prev_aggregation = aggregation[i];
            aggregation[i + 1] += prev_aggregation - lookup_count / (beta + lookup_value);
        } else {
            counts.push(F::zero());
            let prev_aggregation = aggregation[i];
            aggregation[i + 1] += prev_aggregation;
        }
    }

    let counts = zk_patch(counts, d1, rng);
    let aggregation = zk_patch(aggregation, d1, rng);

    if !counts_map.is_empty() {
        return Err(ProverError::ValueNotInTable);
    }

    assert_eq!(F::zero(), aggregation[0]);
    assert_eq!(F::zero(), aggregation[lookup_rows]);

    Ok(ComputedColumns {
        counts,
        aggregation,
        inverses: vec![],
    })
}
