//! This contains the [DomainConstantEvaluations] which is used to provide precomputations to a [ConstraintSystem](super::constraints::ConstraintSystem).

use crate::circuits::domains::EvaluationDomains;
use crate::circuits::polynomials::permutation::zk_polynomial;
use crate::circuits::polynomials::permutation::ZK_ROWS;
use ark_ff::FftField;
use ark_poly::EvaluationDomain;
use ark_poly::UVPolynomial;
use ark_poly::{univariate::DensePolynomial as DP, Evaluations as E, Radix2EvaluationDomain as D};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use super::polynomials::permutation::vanishes_on_last_4_rows;

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
    /// the polynomial that vanishes on the last four rows
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub vanishes_on_last_4_rows: E<F, D<F>>,
    /// zero-knowledge polynomial over domain.d8
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub zkpl: E<F, D<F>>,
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub zkpm: DP<F>,
}

impl<F: FftField> DomainConstantEvaluations<F> {
    pub fn create(domain: EvaluationDomains<F>) -> Option<Self> {
        let poly_x_d1 = DP::from_coefficients_slice(&[F::zero(), F::one()])
            .evaluate_over_domain_by_ref(domain.d8);
        let constant_1_d4 =
            E::<F, D<F>>::from_vec_and_domain(vec![F::one(); domain.d4.size()], domain.d4);
        let constant_1_d8 =
            E::<F, D<F>>::from_vec_and_domain(vec![F::one(); domain.d8.size()], domain.d8);

        let vanishes_on_last_4_rows =
            vanishes_on_last_4_rows(domain.d1).evaluate_over_domain(domain.d8);

        assert!(domain.d1.size > ZK_ROWS);

        // x^3 - x^2(w1+w2+w3) + x(w1w2+w1w3+w2w3) - w1w2w3
        let zkpm = zk_polynomial(domain.d1);
        let zkpl = zkpm.evaluate_over_domain_by_ref(domain.d8);

        Some(DomainConstantEvaluations {
            poly_x_d1,
            constant_1_d4,
            constant_1_d8,
            vanishes_on_last_4_rows,
            zkpl,
            zkpm,
        })
    }
}
