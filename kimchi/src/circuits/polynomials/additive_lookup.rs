use crate::circuits::{
    expr::{prologue::*, Column, ConstantExpr},
    gate::CurrOrNext::*,
    lookup::{
        constraints::LookupConfiguration,
        lookups::{JointLookupSpec, LocalPosition},
        runtime_tables,
    },
};
use ark_ff::{FftField, One, Zero};

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

    let table_contributions = {
        E::cell(Column::AdditiveLookupCount, Curr)
            / (E::Constant(ConstantExpr::Beta) + E::cell(Column::LookupTable, Curr))
    };

    // aggregation[i] = aggregation[i-1] + lookups - table
    let aggreg_equation = {
        let mut res = E::cell(Column::AdditiveLookupAggregation, Next)
            - E::cell(Column::AdditiveLookupAggregation, Next)
            + table_contributions;
        if let Some(lookup_contributions) = lookup_contributions {
            res -= lookup_contributions;
        }
        res
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
