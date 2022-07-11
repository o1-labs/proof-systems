use ark_ff::{FftField, PrimeField};

use ark_poly::Radix2EvaluationDomain as Domain;

use circuit_construction::{generic, Cs, Var};

use crate::types::polynomials::ShiftEval;

/// A saved evaluation of the vanishing polynomial Z_H of H
/// at the point x. In Kimchi this is refered to as zeta1m1
///
/// Note that this polynomial evaluates to the same on any element of the same H coset:
/// i.e. $Z_H(\omega^i * \zeta) = Z_H(\zeta)$ for any $\zeta, i$.
#[derive(Debug, Clone)]
pub struct VanishEval<F: FftField + PrimeField> {
    zhx: Var<F>,
    pub(super) domain: Domain<F>,
}

impl<F: FftField + PrimeField> VanishEval<F> {
    // compute Z_H(x)
    pub fn new<C: Cs<F>>(cs: &mut C, xn: &ShiftEval<F>) -> Self {
        let one: F = F::one();
        let domain = xn.domain;
        let xn: Var<F> = xn.as_ref().clone();

        VanishEval {
            domain: domain,
            zhx: generic!(cs, (xn) : { xn - one = ?}),
        }
    }
}

impl<F: FftField + PrimeField> AsRef<Var<F>> for VanishEval<F> {
    fn as_ref(&self) -> &Var<F> {
        &self.zhx
    }
}
