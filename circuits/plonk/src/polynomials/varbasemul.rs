/*****************************************************************************************************************

This source file implements short Weierstrass curve variable base scalar multiplication custom Plonk polynomials.

*****************************************************************************************************************/

use crate::constraints::ConstraintSystem;
use crate::polynomial::WitnessOverDomains;
use crate::scalars::ProofEvaluations;
use ark_ff::{FftField, SquareRootField, Zero};
use ark_poly::{univariate::DensePolynomial, Evaluations, Radix2EvaluationDomain as D};
use o1_utils::{ExtendedDensePolynomial, ExtendedEvaluations};

impl<F: FftField + SquareRootField> ConstraintSystem<F> {
    // scalar multiplication constraint quotient poly contribution computation
    pub fn vbmul_quot(
        &self,
        polys: &WitnessOverDomains<F>,
        alpha: &[F],
    ) -> (Evaluations<F, D<F>>, Evaluations<F, D<F>>) {
        if self.mul1m.is_zero() && self.mul2m.is_zero() {
            return (self.mul1l.clone(), self.mul2l.clone());
        }

        // 2*xP - λ1^2 + xT
        let tmp = &(&polys.d8.this.l.scale(2_u64.into()) - &polys.d8.this.r.square())
            + &polys.d8.next.r;

        (
            // verify booleanity of the scalar bit
            &(&(&(&polys.d4.this.r - &self.l04) * &polys.d4.this.r).scale(alpha[0])
            +
            // (xP - xT) × λ1 - yP + (yT × (2*b - 1))
            &(&(&(&(&polys.d4.next.l - &polys.d4.this.l) * &polys.d4.next.r) - &polys.d4.next.o) +
                &(&(polys.d4.this.o) * &(&polys.d4.this.r.scale(2_u64.into()) - &self.l04))).scale(alpha[1]))
                * &self.mul1l,
            &(&(
                // (2*yP - (2*xP - λ1^2 + xT) × λ1)^2 - (λ1^2 - xT + xS) * (2*xP - λ1^2 + xT)^2
                &(&polys.d8.this.o.scale(2_u64.into()) - &(&tmp * &polys.d8.this.r)).square()
                    - &(&(&(&polys.d8.this.r.square() - &polys.d8.next.r) + &polys.d8.next.l)
                        * &tmp.square())
            )
                .scale(alpha[2])
                + &(
                    // (xP - xS) × (2*yP - (2*xP - λ1^2 + xT) × λ1) - (yS + yP) * (2*xP - λ1^2 + xT)
                    &(&(&polys.d8.this.l - &polys.d8.next.l)
                        * &(&polys.d8.this.o.scale(2_u64.into()) - &(&tmp * &polys.d8.this.r)))
                        - &(&(&polys.d8.next.o + &polys.d8.this.o) * &tmp)
                )
                    .scale(alpha[3]))
                * &self.mul2l,
        )
    }

    // scalar multiplication constraint linearization poly contribution computation
    pub fn vbmul_scalars(evals: &Vec<ProofEvaluations<F>>, alpha: &[F]) -> Vec<F> {
        // 2*xP - λ1^2 + xT
        let tmp = evals[0].l.double() - &evals[0].r.square() + &evals[1].r;

        vec![
            // verify booleanity of the scalar bit
            (evals[0].r.square() - &evals[0].r) * &alpha[0]
            +
            // (xP - xT) × λ1 = yP - (yT × (2*b - 1))
            ((evals[1].l - &evals[0].l) * &evals[1].r
            -
            &evals[1].o + &(evals[0].o * &(evals[0].r.double() - &F::one()))) * &alpha[1],
            // (2*yP - (2*xP - λ1^2 + xT) × λ1)^2 = (λ1^2 - xT + xS) * (2*xP - λ1^2 + xT)^2
            ((evals[0].o.double() - (tmp * &evals[0].r)).square()
            -
            &((evals[0].r.square() - &evals[1].r + &evals[1].l) * &tmp.square())) * &alpha[2]
            +
            // (xP - xS) × (2*yP - (2*xP - λ1^2 + xT) × λ1) = (yS + yP) * (2*xP - λ1^2 + xT)
            &(((evals[0].l - &evals[1].l) * &(evals[0].o.double() - &(tmp * &evals[0].r))
            -
            ((evals[1].o + &evals[0].o) * &tmp)) * &alpha[3]),
        ]
    }

    // scalar multiplication constraint linearization poly contribution computation
    pub fn vbmul_lnrz(&self, evals: &Vec<ProofEvaluations<F>>, alpha: &[F]) -> DensePolynomial<F> {
        let scalars = Self::vbmul_scalars(evals, alpha);
        &self.mul1m.scale(scalars[0]) + &self.mul2m.scale(scalars[1])
    }
}
