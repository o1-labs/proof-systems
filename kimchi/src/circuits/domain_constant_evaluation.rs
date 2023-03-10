//! This contains the [DomainConstantEvaluations] which is used to provide precomputations to a [ConstraintSystem](super::constraints::ConstraintSystem).

use crate::circuits::domains::EvaluationDomains;
use ark_ff::FftField;
use ark_poly::EvaluationDomain;
use ark_poly::UVPolynomial;
use ark_poly::{univariate::DensePolynomial as DP, Evaluations as E, Radix2EvaluationDomain as D};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use super::polynomials::permutation::{permutation_vanishing_polynomial, vanishes_on_last_n_rows};

#[serde_as]
#[derive(Clone, Serialize, Deserialize, Debug)]
/// pre-computed polynomials that depend only on the chosen field and domain
pub struct DomainConstantEvaluations<F: FftField> {
    /// 1-st Lagrange evaluated over domain.d8
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub poly_x_d1: E<F, D<F>>,
    /// 0-th Lagrange evaluated over domain.d4
    // TODO(mimoo): be consistent with the paper/spec, call it L1 here or call it L0 there
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub constant_1_d4: E<F, D<F>>,
    /// 0-th Lagrange evaluated over domain.d8
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub constant_1_d8: E<F, D<F>>,
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
        let poly_x_d1 = DP::from_coefficients_slice(&[F::zero(), F::one()])
            .evaluate_over_domain_by_ref(domain.d8);
        let constant_1_d4 =
            E::<F, D<F>>::from_vec_and_domain(vec![F::one(); domain.d4.size()], domain.d4);
        let constant_1_d8 =
            E::<F, D<F>>::from_vec_and_domain(vec![F::one(); domain.d8.size()], domain.d8);

        let vanishes_on_zero_knowledge_and_previous_rows =
            vanishes_on_last_n_rows(domain.d1, zk_rows + 1).evaluate_over_domain(domain.d8);

        assert!(domain.d1.size > zk_rows);

        // x^3 - x^2(w1+w2+w3) + x(w1w2+w1w3+w2w3) - w1w2w3
        let permutation_vanishing_polynomial_m =
            permutation_vanishing_polynomial(domain.d1, zk_rows);
        let permutation_vanishing_polynomial_l =
            permutation_vanishing_polynomial_m.evaluate_over_domain_by_ref(domain.d8);

        Some(DomainConstantEvaluations {
            poly_x_d1,
            constant_1_d4,
            constant_1_d8,
            vanishes_on_zero_knowledge_and_previous_rows,
            permutation_vanishing_polynomial_l,
            permutation_vanishing_polynomial_m,
        })
    }
}
