//! This contains the [DomainConstantEvaluations] which is used to provide precomputations to a [ConstraintSystem](super::constraints::ConstraintSystem).

use crate::circuits::domains::EvaluationDomains;
use alloc::vec::Vec;
use ark_ff::FftField;
use ark_poly::{
    univariate::DensePolynomial as DP, EvaluationDomain, Evaluations as E,
    Radix2EvaluationDomain as D,
};
#[cfg(feature = "parallel")]
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use super::polynomials::permutation::permutation_vanishing_polynomial;

/// Evaluate the polynomial `Π (x - root)` (given by its roots) at every point of
/// `d8`, where `x_d8` holds the d8 domain points. For the low-degree vanishing
/// polynomials this is far cheaper than padding to 8n coefficients and running
/// an FFT, and it parallelises trivially over the points.
fn eval_from_roots_over_d8<F: FftField>(x_d8: &[F], roots: &[F], d8: D<F>) -> E<F, D<F>> {
    let evals: Vec<F> = o1_utils::cfg_iter!(x_d8)
        .map(|z| roots.iter().map(|root| *z - *root).product())
        .collect();
    E::from_vec_and_domain(evals, d8)
}

#[serde_as]
#[derive(Clone, Serialize, Deserialize, Debug)]
/// pre-computed polynomials that depend only on the chosen field and domain
pub struct DomainConstantEvaluations<F: FftField> {
    /// the polynomial `x` evaluated over domain.d8 (i.e. the d8 domain points)
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub poly_x_d1: E<F, D<F>>,
    /// the polynomial that vanishes on the zero-knowledge rows and the row before
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub vanishes_on_zero_knowledge_and_previous_rows: E<F, D<F>>,
    /// zero-knowledge polynomial over domain.d8
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub permutation_vanishing_polynomial_l: E<F, D<F>>,
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub permutation_vanishing_polynomial_m: DP<F>,
}

impl<F: FftField> DomainConstantEvaluations<F> {
    pub fn create(domain: EvaluationDomains<F>, zk_rows: u64) -> Option<Self> {
        assert!(domain.d1.size > zk_rows);

        let omega = domain.d1.group_gen;
        let n = domain.d1.size;

        // `x` over d8 is just the d8 domain points (g8^row); recover them from
        // the domain rather than through an FFT.
        let x_d8: Vec<F> = domain.d8.elements().collect();

        // Vanishes on the last (zk_rows + 1) rows: roots omega^{n-(zk_rows+1)} ..
        // omega^{n-1}.
        let zk_roots: Vec<F> = ((n - (zk_rows + 1))..n).map(|i| omega.pow([i])).collect();
        let vanishes_on_zero_knowledge_and_previous_rows =
            eval_from_roots_over_d8(&x_d8, &zk_roots, domain.d8);

        // x^3 - x^2(w1+w2+w3) + x(w1w2+w1w3+w2w3) - w1w2w3, with the three roots
        // omega^{n-zk_rows}, omega^{n-zk_rows+1}, omega^{n-1}.
        let permutation_vanishing_polynomial_m =
            permutation_vanishing_polynomial(domain.d1, zk_rows);
        let permutation_vanishing_polynomial_l = eval_from_roots_over_d8(
            &x_d8,
            &[
                omega.pow([n - zk_rows]),
                omega.pow([n - zk_rows + 1]),
                omega.pow([n - 1]),
            ],
            domain.d8,
        );

        let poly_x_d1 = E::from_vec_and_domain(x_d8, domain.d8);

        Some(DomainConstantEvaluations {
            poly_x_d1,
            vanishes_on_zero_knowledge_and_previous_rows,
            permutation_vanishing_polynomial_l,
            permutation_vanishing_polynomial_m,
        })
    }
}
