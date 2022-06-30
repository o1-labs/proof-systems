use ark_ff::{FftField, PrimeField};

use ark_poly::Radix2EvaluationDomain as Domain;

use circuit_construction::{generic, Cs, Var};

/// A saved evaluation of the vanishing polynomial Z_H of H
/// at the point x. In Kimchi this is refered to as zeta1m1
///
/// Note that this polynomial evaluates to the same on any element of the same H coset:
/// i.e. $Z_H(\omega^i * \zeta) = Z_H(\zeta)$ for any $\zeta, i$.
pub struct VanishEval<F: FftField + PrimeField> {
    xn: Var<F>,
    zhx: Var<F>,
    pub(super) domain: Domain<F>,
}

impl<F: FftField + PrimeField> VanishEval<F> {
    // compute Z_H(x)
    pub fn new<C: Cs<F>>(cs: &mut C, domain: &Domain<F>, x: Var<F>) -> Self {
        let one: F = F::one();
        let xn: Var<F> = cs.pow(x, domain.size);

        VanishEval {
            xn,
            domain: domain.clone(),
            zhx: generic!(cs, (xn) : { xn - one = ?}),
        }
    }
}

impl<F: FftField + PrimeField> AsRef<Var<F>> for VanishEval<F> {
    fn as_ref(&self) -> &Var<F> {
        &self.zhx
    }
}
