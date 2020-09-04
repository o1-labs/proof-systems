/*****************************************************************************************************************

This source file implements short Weierstrass curve endomorphism optimised variable base
scalar multiplication custom Plonk polynomials.

*****************************************************************************************************************/

use algebra::{FftField, SquareRootField};
use ff_fft::{Evaluations, DensePolynomial, Radix2EvaluationDomain as D};
use crate::polynomial::WitnessOverDomains;
use oracle::utils::{EvalUtils, PolyUtils};
use crate::constraints::ConstraintSystem;
use crate::scalars::ProofEvaluations;

impl<F: FftField + SquareRootField> ConstraintSystem<F>
{
    // endomorphism optimised scalar multiplication constraint quotient poly contribution computation
    pub fn endomul_quot(&self, polys: &WitnessOverDomains<F>, alpha: &Vec<F>) -> (Evaluations<F, D<F>>, Evaluations<F, D<F>>)
    {
        if self.emul1m.is_zero() && self.emul2m.is_zero() && self.emul3m.is_zero()
        {return (self.emul1l.clone(), self.emul3l.clone())}

        let one = Evaluations::<F, D<F>>::from_vec_and_domain(vec![F::one(); self.domain.d4.size as usize], self.domain.d4);
        let xr = &(&polys.d8.this.r.pow(2) - &polys.d8.this.l) - &polys.d8.next.r;
        let t = &polys.d8.this.l - &xr;
        let u = &polys.d8.this.o.scale((2 as u64).into()) - &(&t * &polys.d8.this.r);

        (
            // verify booleanity of the scalar bits
            &(&(&(&(&(&polys.d4.this.l - &one) * &polys.d4.this.l).scale(alpha[1])
            +
            &(&(&polys.d4.next.l - &one) * &polys.d4.next.l).scale(alpha[2]))
            +
            // xQ - (1 + (endo - 1) * b2i1) * xT
            &(&polys.d4.next.r - &(&(&one + &polys.d4.this.l.scale(self.endo - &F::one())) * &polys.d4.this.r)).scale(alpha[3]))
            *
            &self.emul1l)
            +
            // (xP - xQ) × λ1 - yP + (yT * (2 * b2i - 1))
            &(&(&(&(&(&polys.d4.next.l - &polys.d4.this.r) * &polys.d4.next.r) - &polys.d4.next.o) +
                &(&polys.d4.this.o * &(&polys.d4.this.l.scale((2 as u64).into()) - &one))) * &self.emul2l)
            ,
            // u^2 - t^2 * (xR + xP + xS)
            &(&(&u.pow(2) - &(&t.pow(2) * &(&(&xr + &polys.d8.this.l) + &polys.d8.next.l))).scale(alpha[1])
            +
            // (xP - xS) * u - t * (yS + yP)
            &(&(&(&polys.d8.this.l - &polys.d8.next.l) * &u) - &(&t * &(&polys.d8.this.o + &polys.d8.next.o))).scale(alpha[2]))
            *
            &self.emul3l
        )
    }

    pub fn endomul_scalars(evals: &Vec<ProofEvaluations<F>>, endo: F, alpha: &Vec<F>) -> Vec<F>
    {
        let xr = evals[0].r.square() - &evals[0].l - &evals[1].r;
        let t = evals[0].l - &xr;
        let u = evals[0].o.double() - &(t * &evals[0].r);

        vec!
        [
            // verify booleanity of the scalar bit
            (evals[0].l.square() - &evals[0].l) * &alpha[1] + &((evals[1].l.square() - &evals[1].l) * &alpha[2])
            +
            // xQ - (1 + (endo - 1) * b2i1) * xT
            ((evals[1].r - &((F::one() + &(evals[0].l * &(endo - &F::one()))) * &evals[0].r)) * &alpha[3])
            ,
            // (xP - xQ) × λ1 - yP + (yT * (2 * b2i - 1))
            (((evals[1].l - &evals[0].r) * &evals[1].r) - &evals[1].o) + &(evals[0].o * &(evals[0].l.double() - &F::one()))
            ,
            // u^2 - t^2 * (xR + xP + xS)
            (u.square() - &(t.square() * &(xr + &evals[0].l + &evals[1].l))) * &alpha[1]
            +
            // (xP - xS) * u - t * (yS + yP)
            &((((evals[0].l - &evals[1].l) * &u) - &(t * &(evals[0].o + &evals[1].o))) * &alpha[2])
        ]
    }

    // endomorphism optimised scalar multiplication constraint linearization poly contribution computation
    pub fn endomul_lnrz(&self, evals: &Vec<ProofEvaluations<F>>, alpha: &Vec<F>) -> DensePolynomial<F>
    {
        let scalars = Self::endomul_scalars(evals, self.endo, alpha);
        &(&self.emul1m.scale(scalars[0]) + &self.emul2m.scale(scalars[1])) + &self.emul3m.scale(scalars[2])
    }
}
