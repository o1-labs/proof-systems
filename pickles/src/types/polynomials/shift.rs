use ark_ff::{FftField, PrimeField};

use ark_poly::Radix2EvaluationDomain as Domain;

use circuit_construction::{Cs, Var};

/// A saved evaluation of the polynomial X^n where n is the size of the domain
#[derive(Debug, Clone)]
pub struct ShiftEval<F: FftField + PrimeField> {
    xn: Var<F>,
    pub(super) domain: Domain<F>,
}

impl<F: FftField + PrimeField> ShiftEval<F> {
    // compute Z_H(x)
    pub fn new<C: Cs<F>>(cs: &mut C, domain: &Domain<F>, x: Var<F>) -> Self {
        let one: F = F::one();
        let xn: Var<F> = cs.pow(x, domain.size);

        ShiftEval {
            xn,
            domain: domain.clone(),
        }
    }
}

impl<F: FftField + PrimeField> AsRef<Var<F>> for ShiftEval<F> {
    fn as_ref(&self) -> &Var<F> {
        &self.xn
    }
}
