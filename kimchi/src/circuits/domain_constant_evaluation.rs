use crate::circuits::domains::EvaluationDomains;
use ark_ff::FftField;
use ark_poly::EvaluationDomain;
use ark_poly::UVPolynomial;
use ark_poly::{univariate::DensePolynomial as DP, Evaluations as E, Radix2EvaluationDomain as D};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use super::polynomials::permutation::vanishes_on_last_4_rows;
use super::zk_polynomial::ZkPolynomial;

#[serde_as]
#[derive(Clone, Serialize, Deserialize, Debug)]
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
}

impl<F: FftField> Default for DomainConstantEvaluations<F> {
    fn default() -> Self {
        let evaluation_domain = E::from_vec_and_domain(vec![], D::<F>::new(0).unwrap());

        DomainConstantEvaluations {
            poly_x_d1: evaluation_domain.clone(),
            constant_1_d4: evaluation_domain.clone(),
            constant_1_d8: evaluation_domain.clone(),
            vanishes_on_last_4_rows: evaluation_domain.clone(),
            zkpl: evaluation_domain.clone(),
        }
    }
}

impl<F: FftField> DomainConstantEvaluations<F> {
    pub fn create(domain: EvaluationDomains<F>) -> Option<Self> {
        let poly_x_d1 = DP::from_coefficients_slice(&[F::zero(), F::one()])
            .evaluate_over_domain_by_ref(domain.d8);
        let constant_1_d4 =
            E::<F, D<F>>::from_vec_and_domain(vec![F::one(); domain.d4.size as usize], domain.d4);
        let constant_1_d8 =
            E::<F, D<F>>::from_vec_and_domain(vec![F::one(); domain.d8.size as usize], domain.d8);

        let vanishes_on_last_4_rows =
            vanishes_on_last_4_rows(domain.d1).evaluate_over_domain(domain.d8);

        let zkp = ZkPolynomial::create(domain).unwrap();
        let zkpl = zkp.zkpm.evaluate_over_domain_by_ref(domain.d8);

        Some(DomainConstantEvaluations {
            poly_x_d1,
            constant_1_d4,
            constant_1_d8,
            vanishes_on_last_4_rows,
            zkpl,
        })
    }
}
