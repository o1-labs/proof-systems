use crate::alphas::{self, ConstraintType};
use crate::circuits::{
    expr::{Column, Expr, Linearization, PolishToken, E},
    gate::{GateType, LookupInfo},
    polynomials::{chacha, complete_add, endomul_scalar, endosclmul, lookup, poseidon, varbasemul},
    wires::*,
};
use ark_ff::{FftField, SquareRootField};
use ark_poly::Radix2EvaluationDomain as D;

/// A structure that packs together the linearization and powers of alpha mapping related to a circuit.
#[derive(Debug, Clone)]
pub struct LinearizationAndAlphas<F> {
    pub linearization: Linearization<Vec<PolishToken<F>>>,
    pub powers_of_alpha: alphas::Builder,
}

impl<F> LinearizationAndAlphas<F>
where
    F: FftField + SquareRootField,
{
    /// Returns the linearization of the circuit, and the powers of alpha mapping
    /// Takes a dummy_lookup_value in case lookups are used, and a boolean indicating if the chacha gate is used.
    pub fn expr_linearization(
        domain: D<F>,
        chacha: bool,
        dummy_lookup_value: Option<&[F]>,
    ) -> Self {
        let evaluated_cols = Self::linearization_columns();

        let (expr, powers_of_alpha) = Self::constraints_expr(domain, chacha, dummy_lookup_value);

        let linearization = expr
            .linearize(evaluated_cols)
            .unwrap()
            .map(|e| e.to_polish());

        Self {
            linearization,
            powers_of_alpha,
        }
    }

    /// Returns the circuit constraints in an intermediate representation, as well as the mapping for the powers of alpha
    pub fn constraints_expr(
        domain: D<F>,
        chacha: bool,
        dummy_lookup_value: Option<&[F]>,
    ) -> (E<F>, alphas::Builder) {
        // register powers of alpha so that we don't reuse them across mutually inclusive constraints
        let mut powers_of_alpha = alphas::Builder::default();

        // gates
        let alphas = powers_of_alpha.register(ConstraintType::Gate, 21);

        let mut expr = poseidon::constraint(alphas.clone().take(15));
        expr += varbasemul::constraint(alphas.clone().take(21));
        expr += complete_add::constraint(alphas.clone().take(7));
        expr += endosclmul::constraint(alphas.clone().take(11));
        expr += endomul_scalar::constraint(alphas.clone().take(11));

        if chacha {
            expr += chacha::constraint_chacha0(alphas.clone().take(5));
            expr += chacha::constraint_chacha1(alphas.clone().take(5));
            expr += chacha::constraint_chacha2(alphas.clone().take(5));
            expr += chacha::constraint_chacha_final(alphas.take(9))
        }

        // permutation
        let _alphas = powers_of_alpha.register(ConstraintType::Permutation, 3);

        // lookup
        if let Some(dummy) = dummy_lookup_value {
            let alphas = powers_of_alpha.register(ConstraintType::Lookup, 7);
            let constraints = lookup::constraints(dummy, domain);
            let combined = Expr::combine_constraints(alphas, constraints);
            expr += combined
        }

        // return the expression
        (expr, powers_of_alpha)
    }

    /// Creates the list of columns that need to be evaluated in the protocol
    /// (in order to linearize the circuit constraint)
    pub fn linearization_columns() -> std::collections::HashSet<Column> {
        let lookup_info = LookupInfo::<F>::create();
        let mut h = std::collections::HashSet::new();
        use Column::*;
        for i in 0..COLUMNS {
            h.insert(Witness(i));
        }
        for i in 0..(lookup_info.max_per_row + 1) {
            h.insert(LookupSorted(i));
        }
        h.insert(Z);
        h.insert(LookupAggreg);
        h.insert(LookupTable);
        h.insert(Index(GateType::Poseidon));
        h.insert(Index(GateType::Generic));
        h
    }
}
