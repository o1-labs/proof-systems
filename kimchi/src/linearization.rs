//! This module implements the linearization.

use crate::alphas::Alphas;
use crate::circuits::argument::{Argument, ArgumentType};
use crate::circuits::lookup;
use crate::circuits::lookup::{
    constraints::LookupConfiguration,
    lookups::{LookupFeatures, LookupInfo, LookupPatterns},
};
use crate::circuits::polynomials::{
    additive_lookup,
    chacha::{ChaCha0, ChaCha1, ChaCha2, ChaChaFinal},
    complete_add::CompleteAdd,
    endomul_scalar::EndomulScalar,
    endosclmul::EndosclMul,
    foreign_field_add::circuitgates::ForeignFieldAdd,
    foreign_field_mul::circuitgates::ForeignFieldMul,
    generic, permutation,
    poseidon::Poseidon,
    range_check::circuitgates::{RangeCheck0, RangeCheck1},
    rot,
    varbasemul::VarbaseMul,
    xor,
};

use crate::circuits::{
    constraints::FeatureFlags,
    expr::{Column, ConstantExpr, Expr, FeatureFlag, Linearization, PolishToken},
    gate::GateType,
    wires::COLUMNS,
};
use ark_ff::{FftField, PrimeField, SquareRootField, Zero};

/// Get the expresion of constraints.
///
/// # Panics
///
/// Will panic if `generic_gate` is not associate with `alpha^0`.
pub fn constraints_expr<F: PrimeField + SquareRootField>(
    feature_flags: Option<&FeatureFlags>,
    generic: bool,
) -> (Expr<ConstantExpr<F>>, Alphas<F>) {
    // register powers of alpha so that we don't reuse them across mutually inclusive constraints
    let mut powers_of_alpha = Alphas::<F>::default();

    // Set up powers of alpha. Only the max number of constraints matters.
    // The gate type argument can just be the zero gate.
    powers_of_alpha.register(
        ArgumentType::Gate(GateType::Zero),
        VarbaseMul::<F>::CONSTRAINTS,
    );

    let mut expr = Poseidon::combined_constraints(&powers_of_alpha);
    expr += VarbaseMul::combined_constraints(&powers_of_alpha);
    expr += CompleteAdd::combined_constraints(&powers_of_alpha);
    expr += EndosclMul::combined_constraints(&powers_of_alpha);
    expr += EndomulScalar::combined_constraints(&powers_of_alpha);

    {
        let chacha_expr = || {
            let mut expr = ChaCha0::combined_constraints(&powers_of_alpha);
            expr += ChaCha1::combined_constraints(&powers_of_alpha);
            expr += ChaCha2::combined_constraints(&powers_of_alpha);
            expr += ChaChaFinal::combined_constraints(&powers_of_alpha);
            expr
        };
        if let Some(feature_flags) = feature_flags {
            if feature_flags.chacha {
                expr += chacha_expr();
            }
        } else {
            expr += Expr::IfFeature(
                FeatureFlag::ChaCha,
                Box::new(chacha_expr()),
                Box::new(Expr::zero()),
            );
        }
    }

    {
        let range_check0_expr = || RangeCheck0::combined_constraints(&powers_of_alpha);

        if let Some(feature_flags) = feature_flags {
            if feature_flags.range_check0 {
                expr += range_check0_expr();
            }
        } else {
            expr += Expr::IfFeature(
                FeatureFlag::RangeCheck0,
                Box::new(range_check0_expr()),
                Box::new(Expr::zero()),
            );
        }
    }

    {
        let range_check1_expr = || RangeCheck1::combined_constraints(&powers_of_alpha);

        if let Some(feature_flags) = feature_flags {
            if feature_flags.range_check1 {
                expr += range_check1_expr();
            }
        } else {
            expr += Expr::IfFeature(
                FeatureFlag::RangeCheck1,
                Box::new(range_check1_expr()),
                Box::new(Expr::zero()),
            );
        }
    }

    {
        let foreign_field_add_expr = || ForeignFieldAdd::combined_constraints(&powers_of_alpha);
        if let Some(feature_flags) = feature_flags {
            if feature_flags.foreign_field_add {
                expr += foreign_field_add_expr();
            }
        } else {
            expr += Expr::IfFeature(
                FeatureFlag::ForeignFieldAdd,
                Box::new(foreign_field_add_expr()),
                Box::new(Expr::zero()),
            );
        }
    }

    {
        let foreign_field_mul_expr = || ForeignFieldMul::combined_constraints(&powers_of_alpha);
        if let Some(feature_flags) = feature_flags {
            if feature_flags.foreign_field_mul {
                expr += foreign_field_mul_expr();
            }
        } else {
            expr += Expr::IfFeature(
                FeatureFlag::ForeignFieldMul,
                Box::new(foreign_field_mul_expr()),
                Box::new(Expr::zero()),
            );
        }
    }

    {
        let xor_expr = || xor::Xor16::combined_constraints(&powers_of_alpha);
        if let Some(feature_flags) = feature_flags {
            if feature_flags.xor {
                expr += xor_expr();
            }
        } else {
            expr += Expr::IfFeature(
                FeatureFlag::Xor,
                Box::new(xor_expr()),
                Box::new(Expr::zero()),
            );
        }
    }

    {
        let rot_expr = || rot::Rot64::combined_constraints(&powers_of_alpha);
        if let Some(feature_flags) = feature_flags {
            if feature_flags.rot {
                expr += rot_expr();
            }
        } else {
            expr += Expr::IfFeature(
                FeatureFlag::Rot,
                Box::new(rot_expr()),
                Box::new(Expr::zero()),
            );
        }
    }

    if generic {
        expr += generic::Generic::combined_constraints(&powers_of_alpha);
    }

    // permutation
    powers_of_alpha.register(ArgumentType::Permutation, permutation::CONSTRAINTS);

    // lookup
    if let Some(feature_flags) = feature_flags {
        if feature_flags.lookup_features.patterns != LookupPatterns::default() {
            let lookup_configuration =
                LookupConfiguration::new(LookupInfo::create(feature_flags.lookup_features));

            {
                let constraints = lookup::constraints::constraints(&lookup_configuration, false);

                // note: the number of constraints depends on the lookup configuration,
                // specifically the presence of runtime tables.
                let constraints_len = u32::try_from(constraints.len())
                    .expect("we always expect a relatively low amount of constraints");

                powers_of_alpha.register(ArgumentType::Lookup, constraints_len);

                let alphas = powers_of_alpha.get_exponents(ArgumentType::Lookup, constraints_len);
                let combined = Expr::combine_constraints(alphas, constraints);

                expr += combined;
            }

            {
                let constraints = additive_lookup::constraints(&lookup_configuration, false);
                let constraints_len = u32::try_from(constraints.len())
                    .expect("we always expect a relatively low amount of constraints");

                powers_of_alpha.register(ArgumentType::AdditiveLookup, constraints_len);

                let alphas =
                    powers_of_alpha.get_exponents(ArgumentType::AdditiveLookup, constraints_len);
                let combined = Expr::combine_constraints(alphas, constraints);

                expr += combined;
            }
        }
    } else {
        let all_features = LookupFeatures {
            patterns: LookupPatterns {
                xor: true,
                chacha_final: true,
                lookup: true,
                range_check: true,
                foreign_field_mul: true,
            },
            uses_runtime_tables: true,
            joint_lookup_used: true,
        };
        let lookup_configuration = LookupConfiguration::new(LookupInfo::create(all_features));

        {
            let constraints = lookup::constraints::constraints(&lookup_configuration, true);

            // note: the number of constraints depends on the lookup configuration,
            // specifically the presence of runtime tables.
            let constraints_len = u32::try_from(constraints.len())
                .expect("we always expect a relatively low amount of constraints");

            powers_of_alpha.register(ArgumentType::Lookup, constraints_len);

            let alphas = powers_of_alpha.get_exponents(ArgumentType::Lookup, constraints_len);
            let combined = Expr::IfFeature(
                FeatureFlag::LookupTables,
                Box::new(Expr::combine_constraints(alphas, constraints)),
                Box::new(Expr::zero()),
            );

            expr += combined;
        }

        {
            let constraints = additive_lookup::constraints(&lookup_configuration, true);
            let constraints_len = u32::try_from(constraints.len())
                .expect("we always expect a relatively low amount of constraints");

            powers_of_alpha.register(ArgumentType::AdditiveLookup, constraints_len);

            let alphas =
                powers_of_alpha.get_exponents(ArgumentType::AdditiveLookup, constraints_len);
            let combined = Expr::IfFeature(
                FeatureFlag::LookupTables,
                Box::new(Expr::combine_constraints(alphas, constraints)),
                Box::new(Expr::zero()),
            );

            expr += combined;
        }
    }

    // the generic gate must be associated with alpha^0
    // to make the later addition with the public input work
    if cfg!(debug_assertions) {
        let mut generic_alphas =
            powers_of_alpha.get_exponents(ArgumentType::Gate(GateType::Generic), 1);
        assert_eq!(generic_alphas.next(), Some(0));
    }

    // Check that the feature flags correctly turn on or off the constraints generated by the given
    // flags.
    if cfg!(feature = "check_feature_flags") {
        if let Some(feature_flags) = feature_flags {
            let (feature_flagged_expr, _) = constraints_expr(None, generic);
            let feature_flagged_expr = feature_flagged_expr.apply_feature_flags(feature_flags);
            assert_eq!(expr, feature_flagged_expr);
        }
    }

    // return the expression
    (expr, powers_of_alpha)
}

/// Adds the polynomials that are evaluated as part of the proof
/// for the linearization to work.
pub fn linearization_columns<F: FftField + SquareRootField>(
    feature_flags: Option<&FeatureFlags>,
) -> std::collections::HashSet<Column> {
    let mut h = std::collections::HashSet::new();
    use Column::*;

    let feature_flags = match feature_flags {
        Some(feature_flags) => *feature_flags,
        None =>
        // Generating using `IfFeature`, turn on all feature flags.
        {
            FeatureFlags {
                chacha: true,
                range_check0: true,
                range_check1: true,
                foreign_field_add: true,
                foreign_field_mul: true,
                xor: true,
                rot: true,
                lookup_features: LookupFeatures {
                    patterns: LookupPatterns {
                        xor: true,
                        chacha_final: true,
                        lookup: true,
                        range_check: true,
                        foreign_field_mul: true,
                    },
                    joint_lookup_used: true,
                    uses_runtime_tables: true,
                },
            }
        }
    };

    // the witness polynomials
    for i in 0..COLUMNS {
        h.insert(Witness(i));
    }

    // the coefficient polynomials
    for i in 0..COLUMNS {
        h.insert(Coefficient(i));
    }

    let lookup_info = if feature_flags.lookup_features.patterns == LookupPatterns::default() {
        None
    } else {
        Some(LookupInfo::create(feature_flags.lookup_features))
    };

    // the lookup polynomials
    if let Some(lookup_info) = lookup_info {
        for i in 0..=lookup_info.max_per_row {
            h.insert(LookupSorted(i));
            h.insert(AdditiveLookupInverse(i));
        }
        h.insert(LookupAggreg);
        h.insert(LookupTable);

        h.insert(AdditiveLookupAggregation);
        h.insert(AdditiveLookupCount);

        // the runtime lookup polynomials
        if lookup_info.features.uses_runtime_tables {
            h.insert(LookupRuntimeTable);
        }
    }

    // the permutation polynomial
    h.insert(Z);

    // the poseidon selector polynomial
    h.insert(Index(GateType::Poseidon));

    // the generic selector polynomial
    h.insert(Index(GateType::Generic));

    h
}

/// Linearize the `expr`.
///
/// If the `feature_flags` argument is `None`, this will generate an expression using the
/// `Expr::IfFeature` variant for each of the flags.
///
/// # Panics
///
/// Will panic if the `linearization` process fails.
pub fn expr_linearization<F: PrimeField + SquareRootField>(
    feature_flags: Option<&FeatureFlags>,
    generic: bool,
) -> (Linearization<Vec<PolishToken<F>>>, Alphas<F>) {
    let evaluated_cols = linearization_columns::<F>(feature_flags);

    let (expr, powers_of_alpha) = constraints_expr(feature_flags, generic);

    let linearization = expr
        .linearize(evaluated_cols)
        .unwrap()
        .map(|e| e.to_polish());

    (linearization, powers_of_alpha)
}
