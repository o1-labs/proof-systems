/*****************************************************************************************************************

This source file implements short Weierstrass curve endomorphism optimised variable base
scalar multiplication custom Plonk polynomials.

*****************************************************************************************************************/

use crate::constraints::ConstraintSystem;
use crate::polynomial::WitnessOverDomains;
use crate::scalars::ProofEvaluations;
use ark_ff::{FftField, SquareRootField, Zero};
use ark_poly::{univariate::DensePolynomial, Evaluations, Radix2EvaluationDomain as D};
use o1_utils::{ExtendedEvaluations, ExtendedDensePolynomial};

impl<F: FftField + SquareRootField> ConstraintSystem<F> {
    // endomorphism optimised scalar multiplication constraint quotient poly contribution computation
    pub fn endomul_quot(
        &self,
        polys: &WitnessOverDomains<F>,
        alpha: &[F],
    ) -> (Evaluations<F, D<F>>, Evaluations<F, D<F>>) {
        if self.emul1m.is_zero() && self.emul2m.is_zero() && self.emul3m.is_zero() {
            return (self.emul1l.clone(), self.emul3l.clone());
        }

        let xr = &(&polys.d8.this.r.square() - &polys.d8.this.l) - &polys.d8.next.r;
        let t = &polys.d8.this.l - &xr;
        let u = &polys.d8.this.o.scale((2 as u64).into()) - &(&t * &polys.d8.this.r);

        (
            // verify booleanity of the scalar bits
            &(&(&(&(&(&polys.d4.this.l - &self.l04) * &polys.d4.this.l).scale(alpha[0])
            +
            &(&(&polys.d4.next.l - &self.l04) * &polys.d4.next.l).scale(alpha[1]))
            +
            // xQ - (1 + (endo - 1) * b2i1) * xT
            &(&polys.d4.next.r - &(&(&self.l04 + &polys.d4.this.l.scale(self.endo - &F::one())) * &polys.d4.this.r)).scale(alpha[2]))
            *
            &self.emul1l)
            +
            // (xP - xQ) × λ1 - yP + (yT * (2 * b2i - 1))
            &(&(&(&(&(&polys.d4.next.l - &polys.d4.this.r) * &polys.d4.next.r) - &polys.d4.next.o) +
                &(&polys.d4.this.o * &(&polys.d4.this.l.scale((2 as u64).into()) - &self.l04))) * &self.emul2l).scale(alpha[3]),
            // u^2 - t^2 * (xR + xP + xS)
            &(&(&u.square() - &(&t.square() * &(&(&xr + &polys.d8.this.l) + &polys.d8.next.l))).scale(alpha[4])
            +
            // (xP - xS) * u - t * (yS + yP)
            &(&(&(&polys.d8.this.l - &polys.d8.next.l) * &u) - &(&t * &(&polys.d8.this.o + &polys.d8.next.o))).scale(alpha[5]))
                * &self.emul3l,
        )
    }

    pub fn endomul_scalars(evals: &Vec<ProofEvaluations<F>>, endo: F, alpha: &[F]) -> Vec<F> {
        let xr = evals[0].r.square() - &evals[0].l - &evals[1].r;
        let t = evals[0].l - &xr;
        let u = evals[0].o.double() - &(t * &evals[0].r);

        vec![
            // verify booleanity of the scalar bit
            (evals[0].l.square() - &evals[0].l) * &alpha[0] + &((evals[1].l.square() - &evals[1].l) * &alpha[1])
            +
            // xQ - (1 + (endo - 1) * b2i1) * xT
            ((evals[1].r - &((F::one() + &(evals[0].l * &(endo - &F::one()))) * &evals[0].r)) * &alpha[2]),
            // (xP - xQ) × λ1 - yP + (yT * (2 * b2i - 1))
            ((((evals[1].l - &evals[0].r) * &evals[1].r) - &evals[1].o)
                + &(evals[0].o * &(evals[0].l.double() - &F::one())))
                * &alpha[3],
            // u^2 - t^2 * (xR + xP + xS)
            (u.square() - &(t.square() * &(xr + &evals[0].l + &evals[1].l))) * &alpha[4]
            +
            // (xP - xS) * u - t * (yS + yP)
            &((((evals[0].l - &evals[1].l) * &u) - &(t * &(evals[0].o + &evals[1].o))) * &alpha[5]),
        ]
    }

    // endomorphism optimised scalar multiplication constraint linearization poly contribution computation
    pub fn endomul_lnrz(
        &self,
        evals: &Vec<ProofEvaluations<F>>,
        alpha: &[F],
    ) -> DensePolynomial<F> {
        let scalars = Self::endomul_scalars(evals, self.endo, alpha);
        &(&self.emul1m.scale(scalars[0]) + &self.emul2m.scale(scalars[1]))
            + &self.emul3m.scale(scalars[2])
    }
}
