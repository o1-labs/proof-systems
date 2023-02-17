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
use ark_ff::{FftField, PrimeField, Zero};
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
        // This is set up so that on rows that have lookups, chunk will be equal
        // to the product over all lookups `f` in that row of `gamma + f`
        // and
        // on non-lookup rows, will be equal to 1.
        let f_term = |spec: &Vec<JointLookupSpec<_>>| {
            assert!(spec.len() <= lookup_info.max_per_row);

            spec.iter()
                .enumerate()
                .map(|(i, _)| column(Column::AdditiveLookupInverse(i)))
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

    // Compute the inversions corresponding to the table, and create a map from table values to
    // their index in the lookup table.
    let (joint_lookup_value_to_index_map, negative_inverted_lookup_values_offset_by_one) = {
        let mut joint_lookup_value_to_index_map: HashMap<F, usize> = HashMap::new();

        // Optimisation: we will later reuse this as our aggregation, so we initialize it with a
        // placeholder value (one) for batch inversion that we can replace.
        let mut lookup_values_offset_by_one = Vec::with_capacity(d1.size());
        lookup_values_offset_by_one.push(F::one());

        for (i, joint_lookup_value) in joint_lookup_table_d8
            .evals
            .iter()
            .step_by(8)
            .take(lookup_rows)
            .enumerate()
        {
            lookup_values_offset_by_one.push(beta + *joint_lookup_value);
            joint_lookup_value_to_index_map
                .entry(*joint_lookup_value)
                .or_insert(i);
        }
        let mut negative_inverted_lookup_values_offset_by_one = lookup_values_offset_by_one;
        ark_ff::batch_inversion_and_mul(
            &mut negative_inverted_lookup_values_offset_by_one,
            &-F::one(),
        );
        (
            joint_lookup_value_to_index_map,
            negative_inverted_lookup_values_offset_by_one,
        )
    };

    let mut counts = vec![0u64; lookup_rows];
    let mut inverses = vec![Vec::with_capacity(d1.size()); lookup_info.max_per_row];

    let by_row = lookup_info.by_row(gates);

    // Accumulate the counts for each value in the lookup table, and use the index map to look up
    // the precomputed inverses for each looked-up value.
    for (i, spec) in by_row
        .iter()
        .enumerate()
        // avoid zk rows
        .take(lookup_rows)
    {
        let num_lookups = spec.len();
        for (j, joint_lookup) in spec.iter().enumerate() {
            let eval = |pos: LocalPosition| -> F {
                let row = match pos.row {
                    Curr => i,
                    Next => i + 1,
                };
                witness[pos.column][row]
            };
            // Compute the value that will appear in the joint lookup table.
            let joint_lookup_evaluation =
                joint_lookup.evaluate(&joint_combiner, &table_id_combiner, &eval);
            // Find the index of the value in the table
            let index = joint_lookup_value_to_index_map
                .get(&joint_lookup_evaluation)
                .ok_or(ProverError::ValueNotInTable)?;
            // Use the cached inverted values from the table to insert the corresponding inverse.
            inverses[j].push(-negative_inverted_lookup_values_offset_by_one[index + 1]);
            // Increase the count for the lookup entry by one.
            counts[*index] += 1u64;
        }
        for inverses in inverses
            .iter_mut()
            .take(lookup_info.max_per_row)
            .skip(num_lookups)
        {
            inverses.push(F::zero());
        }
    }

    // Convert the usage counts for each entry to a field element.
    let counts: Vec<F> = counts.into_iter().map(Into::into).collect();

    // We have now finished using this as an inversion cache, so we can compute the aggregation.
    let mut aggregation = negative_inverted_lookup_values_offset_by_one;

    // Replace the placeholder in the first entry with the initial value of the aggregation
    // polynomial.
    aggregation[0] = F::zero();

    for (i, spec) in by_row.iter().enumerate().take(lookup_rows) {
        // Scale the table inverse by its number of uses
        aggregation[i + 1] *= counts[i];
        // Cascade the aggregation from the previous row through to this one.
        let acc = aggregation[i];
        aggregation[i + 1] += acc;
        for (j, _) in spec.iter().enumerate() {
            // Add the inverse term for this lookup (already computed above).
            aggregation[i + 1] += inverses[j][i];
        }
    }

    // Add randomness to the last ZK_ROWS rows of each polynomial, to provide zero-knowledge.
    let counts = zk_patch(counts, d1, rng);
    let aggregation = zk_patch(aggregation, d1, rng);
    let inverses = inverses.into_iter().map(|x| zk_patch(x, d1, rng)).collect();

    assert_eq!(F::zero(), aggregation[0]);
    assert_eq!(F::zero(), aggregation[lookup_rows]);

    Ok(ComputedColumns {
        counts,
        aggregation,
        inverses,
    })
}
