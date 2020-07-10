/*****************************************************************************************************************

This source file implements short Weierstrass curve variable base scalar multiplication custom Plonk polynomials.

*****************************************************************************************************************/

use algebra::{FftField, SquareRootField};
use ff_fft::{Evaluations, DensePolynomial, Radix2EvaluationDomain as D};
use crate::polynomials::WitnessOverDomains;
use oracle::utils::{EvalUtils, PolyUtils};
use crate::constraints::ConstraintSystem;
use crate::scalars::ProofEvaluations;

impl<F: FftField + SquareRootField> ConstraintSystem<F> 
{
    // scalar multiplication constraint quotient poly contribution computation
    pub fn vbmul_quot(&self, polys: &WitnessOverDomains<F>, alpha: &Vec<F>) -> (Evaluations<F, D<F>>, Evaluations<F, D<F>>)
    {
        let one = Evaluations::<F, D<F>>::from_vec_and_domain(vec![F::one(); self.domain.d2.size as usize], self.domain.d2);

        // 2*xP - λ1^2 + xT
        let tmp = &(&polys.d4.this.l.scale((2 as u64).into()) - &polys.d4.this.r.pow(2)) + &polys.d4.next.r;

        (
            // verify booleanity of the scalar bit
            &(&(&(&polys.d2.this.r - &one) * &polys.d2.this.r).scale(alpha[6])
            +
            // (xP - xT) × λ1 - yP + (yT × (2*b - 1))
            &(&(&(&(&polys.d2.next.l - &polys.d2.this.l) * &polys.d2.next.r) - &polys.d2.next.o) +
                &(&(polys.d2.this.o) * &(&polys.d2.this.r.scale((2 as u64).into()) - &one))).scale(alpha[7]))
            *
            &self.mul1l
            ,
            &(&(
                // (2*yP - (2*xP - λ1^2 + xT) × λ1)^2 - (λ1^2 - xT + xS) * (2*xP - λ1^2 + xT)^2
                &(&polys.d4.this.o.scale((2 as u64).into()) - &(&tmp * &polys.d4.this.r)).pow(2)
                -
                &(&(&(&polys.d4.this.r.pow(2) - &polys.d4.next.r) + &polys.d4.next.l) * &tmp.pow(2))
            ).scale(alpha[8])
            + 
            &(
                // (xP - xS) × (2*yP - (2*xP - λ1^2 + xT) × λ1) - (yS + yP) * (2*xP - λ1^2 + xT)
                &(&(&polys.d4.this.l - &polys.d4.next.l) * &(&polys.d4.this.o.scale((2 as u64).into()) - &(&tmp * &polys.d4.this.r)))
                -
                &(&(&polys.d4.next.o + &polys.d4.this.o) * &tmp)
            ).scale(alpha[9]))
            *
            &self.mul2l
        )
    }

    // scalar multiplication constraint linearization poly contribution computation
    pub fn vbmul_lnrz(&self, evals: &Vec<ProofEvaluations<F>>, alpha: &Vec<F>) -> DensePolynomial<F>
    {
        // 2*xP - λ1^2 + xT
        let tmp = evals[0].l.double() - &evals[0].r.square() + &evals[1].r;

        &self.mul1m.scale
        (
            // verify booleanity of the scalar bit
            (evals[0].r.square() - &evals[0].r) * &alpha[6]
            +
            // (xP - xT) × λ1 = yP - (yT × (2*b - 1))
            ((evals[1].l - &evals[0].l) * &evals[1].r
            -
            &evals[1].o + &(evals[0].o * &(evals[0].r.double() - &F::one()))) * &alpha[7]
        )
        +
        &self.mul2m.scale
        (
            // (2*yP - (2*xP - λ1^2 + xT) × λ1)^2 = (λ1^2 - xT + xS) * (2*xP - λ1^2 + xT)^2
            ((evals[0].o.double() - (tmp * &evals[0].r)).square()
            -
            &((evals[0].r.square() - &evals[1].r + &evals[1].l) * &tmp.square())) * &alpha[8]
            +
            // (xP - xS) × (2*yP - (2*xP - λ1^2 + xT) × λ1) = (yS + yP) * (2*xP - λ1^2 + xT)
            &(((evals[0].l - &evals[1].l) * &(evals[0].o.double() - &(tmp * &evals[0].r))
            -
            ((evals[1].o + &evals[0].o) * &tmp)) * &alpha[9])
        )
    }
}
