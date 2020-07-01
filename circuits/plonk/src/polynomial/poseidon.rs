/*****************************************************************************************************************

This source file implements Posedon constraint polynomials.

*****************************************************************************************************************/

use algebra::{FftField, SquareRootField};
use ff_fft::{Evaluations, DensePolynomial};
use oracle::{utils::{EvalUtils, PolyUtils}, poseidon::sbox};
use crate::polynomials::WitnessOverDomains;
use crate::constraints::ConstraintSystem;
use crate::scalars::ProofEvaluations;

impl<F: FftField + SquareRootField> ConstraintSystem<F> 
{
    // poseidon quotient poly contribution computation f*(1-W) + f^5*W + c(x) - f(wx)
    pub fn psdn_quot(&self, polys: &WitnessOverDomains<F>, alpha: &Vec<F>) -> DensePolynomial<F>
    {
        let mut l = polys.d4.this.l.clone();
        let mut r = polys.d4.this.r.clone();
        let mut o = polys.d4.this.o.clone();

        l.evals.iter_mut().zip(self.psp.evals.iter()).for_each(|(l, p)| *l = sbox(*l) * p);
        r.evals.iter_mut().zip(self.fpl.evals.iter()).for_each(|(r, p)| *r = sbox(*r) * p);
        o.evals.iter_mut().zip(self.fpl.evals.iter()).for_each(|(o, p)| *o = sbox(*o) * p);

        let mut rows = [&l + &o, &l + &r, &r + &o];

        let mut ret = rows.iter_mut().zip(alpha[1..4].iter()).
            map(|(e, a)| {e.evals.iter_mut().for_each(|e| *e *= a); e}).
            fold(DensePolynomial::<F>::zero().evaluate_over_domain_by_ref(self.domain.d4), |x, y| &x + &y).
            interpolate();

        let ln = &Evaluations::multiply(&[&polys.d2.next.l, &self.ps2], self.domain.d2);
        let rn = &Evaluations::multiply(&[&polys.d2.next.r, &self.ps2], self.domain.d2);
        let on = &Evaluations::multiply(&[&polys.d2.next.o, &self.ps2], self.domain.d2);

        let r = &Evaluations::multiply(&[&polys.d2.this.r, &self.pfl], self.domain.d2);
        let o = &Evaluations::multiply(&[&polys.d2.this.o, &self.pfl], self.domain.d2);

        let mut rows = [o - ln, r - rn, &(r + o) - on];

        ret += &rows.iter_mut().zip(alpha[1..4].iter()).
            map(|(e, a)| {e.evals.iter_mut().for_each(|e| *e *= a); e}).
            fold(DensePolynomial::<F>::zero().evaluate_over_domain_by_ref(self.domain.d2), |x, y| &x + &y).
            interpolate();

        self.rcm.iter().zip(alpha[1..4].iter()).map(|(r, a)| r.scale(*a)).fold(ret, |x, y| &x + &y)
    }

    // poseidon linearization poly contribution computation f*(1-W) + f^5*W + c(x) - f(wx)
    pub fn psdn_lnrz(&self, evals: &Vec<ProofEvaluations<F>>, alpha: &Vec<F>) -> DensePolynomial<F>
    {
        let (l, r, o) = (sbox(evals[0].l), sbox(evals[0].r), sbox(evals[0].o));

        let ret =
            &(&self.fpm.scale((o * &alpha[1]) + &(r * &alpha[2]) + &((r + &o) * &alpha[3])) +
            &self.pfm.scale((evals[0].o * &alpha[1]) + &(evals[0].r * &alpha[2]) + &((evals[0].r + &evals[0].o) * &alpha[3]))) +
            &self.psm.scale(((l - &evals[1].l) * &alpha[1]) + &((l - &evals[1].r) * &alpha[2]) - &(evals[1].o * &alpha[3]));
        
        self.rcm.iter().zip(alpha[1..4].iter()).map(|(r, a)| r.scale(*a)).fold(ret, |x, y| &x + &y)

    }
}
