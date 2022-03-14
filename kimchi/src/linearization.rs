//! This module implements the linearization.

use crate::alphas::Alphas;
use crate::circuits::argument::{Argument, ArgumentType};
use crate::circuits::polynomials::chacha::{ChaCha0, ChaCha1, ChaCha2, ChaChaFinal};
use crate::circuits::polynomials::complete_add::CompleteAdd;
use crate::circuits::polynomials::endomul_scalar::EndomulScalar;
use crate::circuits::polynomials::endosclmul::EndosclMul;
use crate::circuits::polynomials::lookup;
use crate::circuits::polynomials::permutation;
use crate::circuits::polynomials::poseidon::Poseidon;
use crate::circuits::polynomials::varbasemul::VarbaseMul;
use crate::circuits::{
    constraints::LookupConstraintSystem,
    expr::{Column, ConstantExpr, Expr, Linearization, PolishToken},
    gate::GateType,
    wires::*,
};
use ark_ff::{FftField, SquareRootField};
use ark_poly::Radix2EvaluationDomain as D;

pub fn constraints_expr<F: FftField + SquareRootField>(
    domain: D<F>,
    chacha: bool,
    lookup_constraint_system: &Option<LookupConstraintSystem<F>>,
) -> (Expr<ConstantExpr<F>>, Alphas<F>) {
    // register powers of alpha so that we don't reuse them across mutually inclusive constraints
    let mut powers_of_alpha = Alphas::<F>::default();

    // gates
    let highest_constraints = VarbaseMul::<F>::CONSTRAINTS;
    powers_of_alpha.register(
        ArgumentType::Gate(GateType::VarBaseMul),
        highest_constraints,
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

    // permutation
    powers_of_alpha.register(ArgumentType::Permutation, permutation::CONSTRAINTS);

    // lookup
    if let Some(lcs) = lookup_constraint_system.as_ref() {
        powers_of_alpha.register(ArgumentType::Lookup, lookup::CONSTRAINTS);
        let alphas = powers_of_alpha.get_exponents(ArgumentType::Lookup, lookup::CONSTRAINTS);

        let constraints = lookup::constraints(&lcs.dummy_lookup_value, domain, lcs.max_joint_size);
        let combined = Expr::combine_constraints(alphas, constraints);
        expr += combined;
    }

    // return the expression
    (expr, powers_of_alpha)
}

pub fn linearization_columns<F: FftField + SquareRootField>(
    lookup_constraint_system: &Option<LookupConstraintSystem<F>>,
) -> std::collections::HashSet<Column> {
    let mut h = std::collections::HashSet::new();
    use Column::*;
    for i in 0..COLUMNS {
        h.insert(Witness(i));
    }
    match lookup_constraint_system.as_ref() {
        None => (),
        Some(lcs) => {
            for i in 0..(lcs.max_lookups_per_row + 1) {
                h.insert(LookupSorted(i));
            }
        }
    }
    h.insert(Z);
    h.insert(LookupAggreg);
    h.insert(LookupTable);
    h.insert(Index(GateType::Poseidon));
    h.insert(Index(GateType::Generic));
    h
}

pub fn expr_linearization<F: FftField + SquareRootField>(
    domain: D<F>,
    chacha: bool,
    lookup_constraint_system: &Option<LookupConstraintSystem<F>>,
) -> (Linearization<Vec<PolishToken<F>>>, Alphas<F>) {
    let evaluated_cols = linearization_columns::<F>(lookup_constraint_system);

    let (expr, powers_of_alpha) = constraints_expr(domain, chacha, lookup_constraint_system);

    let linearization = expr
        .linearize(evaluated_cols)
        .unwrap()
        .map(|e| e.to_polish());

    (linearization, powers_of_alpha)
}
