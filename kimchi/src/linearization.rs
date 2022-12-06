//! This module implements the linearization.

use crate::alphas::Alphas;
use crate::circuits::argument::{Argument, ArgumentType};
use crate::circuits::lookup;
use crate::circuits::lookup::constraints::LookupConfiguration;
// TODO JES: CLEAN UP
use crate::circuits::polynomials::chacha::{ChaCha0, ChaCha1, ChaCha2, ChaChaFinal};
use crate::circuits::polynomials::complete_add::CompleteAdd;
use crate::circuits::polynomials::endomul_scalar::EndomulScalar;
use crate::circuits::polynomials::endosclmul::EndosclMul;
use crate::circuits::polynomials::foreign_field_add::circuitgates::ForeignFieldAdd;
use crate::circuits::polynomials::foreign_field_mul::circuitgates::ForeignFieldMul;
use crate::circuits::polynomials::poseidon::Poseidon;
use crate::circuits::polynomials::range_check;
use crate::circuits::polynomials::varbasemul::VarbaseMul;
use crate::circuits::polynomials::{generic, permutation, xor};
use crate::circuits::{
    constraints::FeatureFlags,
    expr::{Column, ConstantExpr, Expr, FeatureFlag, Linearization, PolishToken},
    gate::GateType,
    wires::COLUMNS,
};
use ark_ff::{FftField, PrimeField, SquareRootField};

/// Get the expresion of constraints.
///
/// # Panics
///
/// Will panic if `generic_gate` is not associate with `alpha^0`.
pub fn constraints_expr<F: PrimeField + SquareRootField>(
    feature_flags: Option<&FeatureFlags<F>>,
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
            expr += Expr::EnabledIf(FeatureFlag::ChaCha, Box::new(chacha_expr()));
        }
    }

    {
        let range_check_expr = || range_check::gadget::combined_constraints(&powers_of_alpha);

        if let Some(feature_flags) = feature_flags {
            if feature_flags.range_check {
                expr += range_check_expr();
            }
        } else {
            expr += Expr::EnabledIf(FeatureFlag::RangeCheck, Box::new(range_check_expr()));
        }
    }

    {
        let foreign_field_add_expr = || ForeignFieldAdd::combined_constraints(&powers_of_alpha);
        if let Some(feature_flags) = feature_flags {
            if feature_flags.foreign_field_add {
                expr += foreign_field_add_expr();
            }
        } else {
            expr += Expr::EnabledIf(
                FeatureFlag::ForeignFieldAdd,
                Box::new(foreign_field_add_expr()),
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
            expr += Expr::EnabledIf(
                FeatureFlag::ForeignFieldMul,
                Box::new(foreign_field_mul_expr()),
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
            expr += Expr::EnabledIf(FeatureFlag::Xor, Box::new(xor_expr()));
        }
    }

    if generic {
        expr += generic::Generic::combined_constraints(&powers_of_alpha);
    }

    // permutation
    powers_of_alpha.register(ArgumentType::Permutation, permutation::CONSTRAINTS);

    // lookup
    if let Some(lcs) = feature_flags.and_then(|x| x.lookup_configuration.as_ref()) {
        let constraints = lookup::constraints::constraints(lcs);

        // note: the number of constraints depends on the lookup configuration,
        // specifically the presence of runtime tables.
        let constraints_len = u32::try_from(constraints.len())
            .expect("we always expect a relatively low amount of constraints");

        powers_of_alpha.register(ArgumentType::Lookup, constraints_len);

        let alphas = powers_of_alpha.get_exponents(ArgumentType::Lookup, constraints_len);
        let combined = Expr::combine_constraints(alphas, constraints);

        expr += combined;
    }

    // the generic gate must be associated with alpha^0
    // to make the later addition with the public input work
    if cfg!(debug_assertions) {
        let mut generic_alphas =
            powers_of_alpha.get_exponents(ArgumentType::Gate(GateType::Generic), 1);
        assert_eq!(generic_alphas.next(), Some(0));
    }

    // return the expression
    (expr, powers_of_alpha)
}

/// Adds the polynomials that are evaluated as part of the proof
/// for the linearization to work.
pub fn linearization_columns<F: FftField + SquareRootField>(
    lookup_constraint_system: Option<&LookupConfiguration<F>>,
) -> std::collections::HashSet<Column> {
    let mut h = std::collections::HashSet::new();
    use Column::*;

    // the witness polynomials
    for i in 0..COLUMNS {
        h.insert(Witness(i));
    }

    // the coefficient polynomials
    for i in 0..COLUMNS {
        h.insert(Coefficient(i));
    }

    // the lookup polynomials
    if let Some(lcs) = &lookup_constraint_system {
        for i in 0..=lcs.lookup_info.max_per_row {
            h.insert(LookupSorted(i));
        }
        h.insert(LookupAggreg);
        h.insert(LookupTable);

        // the runtime lookup polynomials
        if lcs.lookup_info.uses_runtime_tables {
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
/// `Expr::EnabledIf` variant for each of the flags.
///
/// # Panics
///
/// Will panic if the `linearization` process fails.
pub fn expr_linearization<F: PrimeField + SquareRootField>(
    feature_flags: Option<&FeatureFlags<F>>,
    generic: bool,
) -> (Linearization<Vec<PolishToken<F>>>, Alphas<F>) {
    let evaluated_cols =
        linearization_columns::<F>(feature_flags.and_then(|x| x.lookup_configuration.as_ref()));

    let (expr, powers_of_alpha) = constraints_expr(feature_flags, generic);

    let linearization = expr
        .linearize(evaluated_cols)
        .unwrap()
        .map(|e| e.to_polish());

    (linearization, powers_of_alpha)
}
