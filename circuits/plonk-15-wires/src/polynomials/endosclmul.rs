/*****************************************************************************************************************

This source file implements short Weierstrass curve endomorphism optimised variable base
scalar multiplication custom Plonk polynomials.

EVBSM gate constrains

    b1*(b1-1) = 0
    b2*(b2-1) = 0
    (xp - (1 + (endo - 1) * b2) * xt) * s1 = yp – (2*b1-1)*yt
    s1^2 - s2^2 = (1 + (endo - 1) * b2) * xt - xs
    (2*xp + (1 + (endo - 1) * b2) * xt – s1^2) * (s1 + s2) = 2*yp
    (xp – xs) * s2 = ys + yp

Permutation constrains

    -> b1(i)
    -> b2(i+1)
    -> xt(i) -> xt(i+2) -> … -> xt(255)
    -> yt(i) -> yt(i+2) -> … -> yt(255)
    -> xp(i)
    -> xp(i+2) -> xs(i) ->
    -> yp(i)
    -> yp(i+2) -> ys(i) ->
    xs(255) ->
    ys(255) ->

The constrains above are derived from the following EC Affine arithmetic equations:

    (xq - xp) * s1 = yq - yp
    s1 * s1 = xp + xq + x1
    (xp – x1) * s1 = y1 + yp

    (x1 – xp) * s2 = y1 – yp
    s2 * s2 = xp + x1 + xs
    (xp – xs) * s2 = ys + yp

    =>

    (xq - xp) * s1 = yq - yp
    s1^2 = xp + xq + x1
    (xp – x1) * (s1 + s2) = 2*yp
    s2^2 = xp + x1 + xs
    (xp – xs) * s2 = ys + yp

    =>

    (xq - xp) * s1 = yq - yp
    s1^2 - s2^2 = xq - xs
    (2*xp + xq – s1^2) * (s1 + s2) = 2*yp
    (xp – xs) * s2 = ys + yp

    *****************************************************************************************************************/

use algebra::{FftField, SquareRootField};
use ff_fft::{Evaluations, DensePolynomial, Radix2EvaluationDomain as D};
use crate::polynomial::WitnessOverDomains;
use oracle::utils::{EvalUtils, PolyUtils};
use crate::nolookup::constraints::ConstraintSystem;
use crate::nolookup::scalars::ProofEvaluations;

impl<F: FftField + SquareRootField> ConstraintSystem<F>
{
    // endomorphism optimised scalar multiplication constraint quotient poly contribution computation
    pub fn endomul_quot(&self, polys: &WitnessOverDomains<F>, alpha: &[F]) -> Evaluations<F, D<F>>
    {
        if self.emulm.is_zero() {return self.zero4.clone()}
        let xq = &(&(&self.l04 + &polys.d4.next.w[4].scale(self.endo - F::one())) * &polys.d4.this.w[0]);

        // verify booleanity of the scalar bits
        &(&(&(&(&(&(&polys.d4.this.w[4] - &polys.d4.this.w[4].pow(2)).scale(alpha[0])
        +
        &(&polys.d4.next.w[4] - &polys.d4.next.w[4].pow(2)).scale(alpha[1]))
        +
        // (xp - (1 + (endo - 1) * b2) * xt) * s1 = yp – (2*b1-1)*yt
        &(&(&(&(&polys.d4.next.w[2] - xq) * &polys.d4.this.w[2]) - &polys.d4.next.w[3]) +
            &(&polys.d4.this.w[1] * &(&polys.d4.this.w[4].scale(F::from(2 as u64)) - &self.l04))).scale(alpha[2]))
        +
        // s1^2 - s2^2 = (1 + (endo - 1) * b2) * xt - xs
        &(&(&(&polys.d4.this.w[2].pow(2) - &polys.d4.this.w[3].pow(2)) - xq) + &polys.d4.next.w[0]).scale(alpha[3]))
        +
        // (2*xp + (1 + (endo - 1) * b2) * xt – s1^2) * (s1 + s2) = 2*yp
        &(&(&(&(&polys.d4.next.w[2].scale(F::from(2 as u64)) + xq) - &polys.d4.this.w[2].pow(2)) *
            &(&polys.d4.this.w[2] + &polys.d4.this.w[3])) - &polys.d4.next.w[3].scale(F::from(2 as u64))).scale(alpha[4]))
        +
        // (xp – xs) * s2 = ys + yp
        &(&(&(&(&polys.d4.next.w[2] - &polys.d4.next.w[0]) * &polys.d4.this.w[3]) -
            &polys.d4.next.w[1]) - &polys.d4.next.w[3]).scale(alpha[5]))
        *
        &self.emull
    }

    pub fn endomul_scalars(evals: &Vec<ProofEvaluations<F>>, endo: F, alpha: &[F]) -> F
    {
        let xq = (F::one() + &(evals[1].w[4] * &(endo - F::one()))) * &evals[0].w[0];

        // verify booleanity of the scalar bits
        (evals[0].w[4] - &evals[0].w[4].square()) * &alpha[0]
        +
        &((evals[1].w[4] - &evals[1].w[4].square()) * &alpha[1])
        +
        // (xp - (1 + (endo - 1) * b2) * xt) * s1 = yp – (2*b1-1)*yt
        &(((evals[1].w[2] - xq) * &evals[0].w[2] - &evals[1].w[3] +
            &(evals[0].w[1] * &(evals[0].w[4].double() - &F::one()))) * &alpha[2])
        +
        // s1^2 - s2^2 = (1 + (endo - 1) * b2) * xt - xs
        &((((evals[0].w[2].square() - &evals[0].w[3].square()) - xq) + &evals[1].w[0]) * &alpha[3])
        +
        // (2*xp + (1 + (endo - 1) * b2) * xt – s1^2) * (s1 + s2) = 2*yp
        &((((evals[1].w[2].double() + xq) - &evals[0].w[2].square()) *
            &(evals[0].w[2] + &evals[0].w[3]) - &evals[1].w[3].double()) * &alpha[4])
        +
        // (xp – xs) * s2 = ys + yp
        &((((evals[1].w[2] - &evals[1].w[0]) * &evals[0].w[3]) -
            &evals[1].w[1] - &evals[1].w[3]) * &alpha[5])
    }

    // endomorphism optimised scalar multiplication constraint linearization poly contribution computation
    pub fn endomul_lnrz(&self, evals: &Vec<ProofEvaluations<F>>, alpha: &[F]) -> DensePolynomial<F>
    {
        self.emulm.scale(Self::endomul_scalars(evals, self.endo, alpha))
    }
}
