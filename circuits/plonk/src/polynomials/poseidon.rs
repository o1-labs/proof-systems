/*****************************************************************************************************************

This source file implements Posedon constraint polynomials.

*****************************************************************************************************************/

use algebra::{FftField, SquareRootField};
use ff_fft::{Evaluations, DensePolynomial, Radix2EvaluationDomain as D};
use oracle::{utils::PolyUtils, poseidon::sbox};
use crate::polynomial::WitnessOverDomains;
use crate::constraints::ConstraintSystem;
use crate::scalars::ProofEvaluations;

impl<F: FftField + SquareRootField> ConstraintSystem<F> 
{
    // poseidon quotient poly contribution computation f*(1-W) + f^5*W + c(x) - f(wx)
    pub fn psdn_quot
    (
        &self, polys: &WitnessOverDomains<F>,
        alpha: &Vec<F>
    ) -> (Evaluations<F, D<F>>, Evaluations<F, D<F>>, DensePolynomial<F>)
    {
        let mut l = polys.d8.this.l.clone();
        let mut r = polys.d8.this.r.clone();
        let mut o = polys.d8.this.o.clone();

        l.evals.iter_mut().zip(self.psp.evals.iter()).for_each(|(l, p)| *l = sbox(*l) * p);
        r.evals.iter_mut().zip(self.fpl.evals.iter()).for_each(|(r, p)| *r = sbox(*r) * p);
        o.evals.iter_mut().zip(self.fpl.evals.iter()).for_each(|(o, p)| *o = sbox(*o) * p);

        let mut rows = [&l + &o, &l + &r, &r + &o];

        let pos4 = rows.iter_mut().zip(alpha[1..4].iter()).
            map(|(e, a)| {e.evals.iter_mut().for_each(|e| *e *= a); e}).
            fold(DensePolynomial::<F>::zero().evaluate_over_domain_by_ref(self.domain.d8), |x, y| &x + &y);

        let ln = &(&polys.d4.next.l * &self.ps2);
        let rn = &(&polys.d4.next.r * &self.ps2);
        let on = &(&polys.d4.next.o * &self.ps2);

        let r = &(&polys.d4.this.r * &self.pfl);
        let o = &(&polys.d4.this.o * &self.pfl);

        let mut rows = [o - ln, r - rn, &(r + o) - on];

        let pos2 = rows.iter_mut().zip(alpha[1..4].iter()).
            map(|(e, a)| {e.evals.iter_mut().for_each(|e| *e *= a); e}).
            fold(DensePolynomial::<F>::zero().evaluate_over_domain_by_ref(self.domain.d4), |x, y| &x + &y);

        let posp = self.rcm.iter().zip(alpha[1..4].iter()).map(|(r, a)| r.scale(*a)).fold(DensePolynomial::<F>::zero(), |x, y| &x + &y);

        (pos2, pos4, posp)
    }

    pub fn psdn_scalars(evals: &Vec<ProofEvaluations<F>>, alpha: &Vec<F>) -> Vec<F>
    {
        let (l, r, o) = (sbox(evals[0].l), sbox(evals[0].r), sbox(evals[0].o));
        vec!
        [
            (o * &alpha[1]) + &(r * &alpha[2]) + &((r + &o) * &alpha[3]),
            (evals[0].o * &alpha[1]) + &(evals[0].r * &alpha[2]) + &((evals[0].r + &evals[0].o) * &alpha[3]),
            ((l - &evals[1].l) * &alpha[1]) + &((l - &evals[1].r) * &alpha[2]) - &(evals[1].o * &alpha[3]),
            alpha[1],
            alpha[2],
            alpha[3]
        ]
    }

    // poseidon linearization poly contribution computation f*(1-W) + f^5*W + c(x) - f(wx)
    pub fn psdn_lnrz(&self, evals: &Vec<ProofEvaluations<F>>, alpha: &Vec<F>) -> DensePolynomial<F>
    {
        let scalars = Self::psdn_scalars(evals, alpha);
        let ret =
            &(&self.fpm.scale(scalars[0]) +
            &self.pfm.scale(scalars[1])) +
            &self.psm.scale(scalars[2]);
        
        self.rcm.iter().zip(alpha[1..4].iter()).map(|(r, a)| r.scale(*a)).fold(ret, |x, y| &x + &y)
    }
}
