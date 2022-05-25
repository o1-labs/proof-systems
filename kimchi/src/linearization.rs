//! This module implements the linearization.

use crate::alphas::Alphas;
use crate::circuits::argument::{Argument, ArgumentType};
use crate::circuits::lookup;
use crate::circuits::lookup::constraints::LookupConfiguration;
use crate::circuits::polynomials::chacha::{ChaCha0, ChaCha1, ChaCha2, ChaChaFinal};
use crate::circuits::polynomials::complete_add::CompleteAdd;
use crate::circuits::polynomials::endomul_scalar::EndomulScalar;
use crate::circuits::polynomials::endosclmul::EndosclMul;
use crate::circuits::polynomials::permutation;
use crate::circuits::polynomials::poseidon::Poseidon;
use crate::circuits::polynomials::range_check;
use crate::circuits::polynomials::varbasemul::VarbaseMul;
use crate::circuits::{
    expr::{Column, ConstantExpr, Expr, Linearization, PolishToken},
    gate::GateType,
    wires::*,
};
use ark_ff::{FftField, SquareRootField};
use ark_poly::Radix2EvaluationDomain as D;

pub fn constraints_expr<F: FftField + SquareRootField>(
    domain: D<F>,
    chacha: bool,
    range_check: bool,
    lookup_constraint_system: Option<&LookupConfiguration<F>>,
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

    if chacha {
        expr += ChaCha0::combined_constraints(&powers_of_alpha);
        expr += ChaCha1::combined_constraints(&powers_of_alpha);
        expr += ChaCha2::combined_constraints(&powers_of_alpha);
        expr += ChaChaFinal::combined_constraints(&powers_of_alpha);
    }

    if range_check {
        expr += range_check::combined_constraints(&powers_of_alpha);
    }

    // permutation
    powers_of_alpha.register(ArgumentType::Permutation, permutation::CONSTRAINTS);

    // lookup
    if let Some(lcs) = lookup_constraint_system.as_ref() {
        let constraints = lookup::constraints::constraints(lcs, domain);

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

    // the lookup polynomials
    if let Some(lcs) = &lookup_constraint_system {
        for i in 0..(lcs.max_lookups_per_row + 1) {
            h.insert(LookupSorted(i));
        }
        h.insert(LookupAggreg);
        h.insert(LookupTable);

        // the runtime lookup polynomials
        if lcs.runtime_tables.is_some() {
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

pub fn expr_linearization<F: FftField + SquareRootField>(
    domain: D<F>,
    chacha: bool,
    range_check: bool,
    lookup_constraint_system: Option<&LookupConfiguration<F>>,
) -> (Linearization<Vec<PolishToken<F>>>, Alphas<F>) {
    let evaluated_cols = linearization_columns::<F>(lookup_constraint_system);

    let (expr, powers_of_alpha) =
        constraints_expr(domain, chacha, range_check, lookup_constraint_system);

    let linearization = expr
        .linearize(evaluated_cols)
        .unwrap()
        .map(|e| e.to_polish());

    (linearization, powers_of_alpha)
}
