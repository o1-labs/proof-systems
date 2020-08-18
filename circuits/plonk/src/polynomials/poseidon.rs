/*****************************************************************************************************************

This source file implements Poseidon constraint polynomials.

*****************************************************************************************************************/

use algebra::{FftField, SquareRootField};
use ff_fft::{Evaluations, DensePolynomial, Radix2EvaluationDomain as D};
use oracle::{utils::{PolyUtils, EvalUtils}, poseidon::sbox};
use crate::polynomial::WitnessOverDomains;
use crate::constraints::ConstraintSystem;
use crate::scalars::ProofEvaluations;

impl<F: FftField + SquareRootField> ConstraintSystem<F>
{
    // poseidon quotient poly contribution computation f^5 + c(x) - f(wx)
    pub fn psdn_quot
    (
        &self, polys: &WitnessOverDomains<F>,
        alpha: &Vec<F>
    ) -> (Evaluations<F, D<F>>, Evaluations<F, D<F>>, DensePolynomial<F>)
    {
        if self.psm.is_zero() {return (self.ps4.clone(), self.ps8.clone(), DensePolynomial::<F>::zero())}

        let mut l = polys.d8.this.l.clone();
        let mut r = polys.d8.this.r.clone();
        let mut o = polys.d8.this.o.clone();

        l.evals.iter_mut().for_each(|l| *l = sbox(*l));
        r.evals.iter_mut().for_each(|r| *r = sbox(*r));
        o.evals.iter_mut().for_each(|o| *o = sbox(*o));

        (
            &self.ps4 * &(&(&polys.d4.next.l.scale(-alpha[1]) - &polys.d4.next.r.scale(alpha[2])) - &polys.d4.next.o.scale(alpha[3])),
            &self.ps8 * &(&(&(&l + &o).scale(alpha[1]) + &(&l + &r).scale(alpha[2])) + &(&r + &o).scale(alpha[3])),
            &(&self.rcm[0].scale(alpha[1]) + &self.rcm[1].scale(alpha[2])) + &self.rcm[2].scale(alpha[3])
        )
    }

    pub fn psdn_scalars(evals: &Vec<ProofEvaluations<F>>, alpha: &Vec<F>) -> Vec<F>
    {
        let (l, r, o) = (sbox(evals[0].l), sbox(evals[0].r), sbox(evals[0].o));
        vec!
        [
            ((l + &o - &evals[1].l) * &alpha[1]) + &((l + &r - &evals[1].r) * &alpha[2]) + &((r + &o - &evals[1].o) * &alpha[3]),
            alpha[1],
            alpha[2],
            alpha[3]
        ]
    }

    // poseidon linearization poly contribution computation f^5 + c(x) - f(wx)
    pub fn psdn_lnrz(&self, evals: &Vec<ProofEvaluations<F>>, alpha: &Vec<F>) -> DensePolynomial<F>
    {
        self.rcm.iter().zip(alpha[1..4].iter()).map(|(r, a)| r.scale(*a)).
            fold(self.psm.scale(Self::psdn_scalars(evals, alpha)[0]), |x, y| &x + &y)
    }
}
