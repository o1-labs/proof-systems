use crate::circuits::constraints::ZK_ROWS;
use crate::circuits::domains::EvaluationDomains;
use ark_ff::FftField;
use ark_poly::UVPolynomial;
use ark_poly::{univariate::DensePolynomial as DP, Evaluations as E, Radix2EvaluationDomain as D};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

#[serde_as]
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ConstantPolynomial<F: FftField> {
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub l1: E<F, D<F>>,
    /// 0-th Lagrange evaluated over domain.d4
    // TODO(mimoo): be consistent with the paper/spec, call it L1 here or call it L0 there
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub l04: E<F, D<F>>,
    /// 0-th Lagrange evaluated over domain.d8
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub l08: E<F, D<F>>,
    /// zero evaluated over domain.d8
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub zero4: E<F, D<F>>,
    /// zero evaluated over domain.d8
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub zero8: E<F, D<F>>,
    /// the polynomial that vanishes on the last four rows
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub vanishes_on_last_4_rows: E<F, D<F>>,
}

/// The polynomial
/// (x - w^{n - 4}) (x - w^{n - 3}) * (x - w^{n - 2}) * (x - w^{n - 1})
pub fn vanishes_on_last_4_rows<F: FftField>(domain: D<F>) -> DP<F> {
    let x = DP::from_coefficients_slice(&[F::zero(), F::one()]);
    let c = |a: F| DP::from_coefficients_slice(&[a]);
    let w4 = domain.group_gen.pow(&[domain.size - (ZK_ROWS + 1)]);
    let w3 = domain.group_gen * w4;
    let w2 = domain.group_gen * w3;
    let w1 = domain.group_gen * w2;
    &(&(&x - &c(w1)) * &(&x - &c(w2))) * &(&(&x - &c(w3)) * &(&x - &c(w4)))
}

impl<F: FftField> ConstantPolynomial<F> {
    pub fn create(domain: EvaluationDomains<F>) -> Option<Self> {
        let l1 = DP::from_coefficients_slice(&[F::zero(), F::one()])
            .evaluate_over_domain_by_ref(domain.d8);
        // TODO: These are all unnecessary. Remove
        let l04 =
            E::<F, D<F>>::from_vec_and_domain(vec![F::one(); domain.d4.size as usize], domain.d4);
        let l08 =
            E::<F, D<F>>::from_vec_and_domain(vec![F::one(); domain.d8.size as usize], domain.d8);
        let zero4 =
            E::<F, D<F>>::from_vec_and_domain(vec![F::zero(); domain.d4.size as usize], domain.d4);
        let zero8 =
            E::<F, D<F>>::from_vec_and_domain(vec![F::zero(); domain.d8.size as usize], domain.d8);

        let vanishes_on_last_4_rows =
            vanishes_on_last_4_rows(domain.d1).evaluate_over_domain(domain.d8);

        Some(ConstantPolynomial {
            l1,
            l04,
            l08,
            zero4,
            zero8,
            vanishes_on_last_4_rows,
        })
    }
}
