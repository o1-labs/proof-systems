/*****************************************************************************************************************

This source file implements short Weierstrass curve endomorphism optimised variable base
scalar multiplication custom Plonk polynomials.

EVBSM gate constraints

    b1*(b1-1) = 0
    b2*(b2-1) = 0
    (xp - (1 + (endo - 1) * b2) * xt) * s1 = yp – (2*b1-1)*yt
    s1^2 - s2^2 = (1 + (endo - 1) * b2) * xt - xs
    (2*xp + (1 + (endo - 1) * b2) * xt – s1^2) * (s1 + s2) = 2*yp
    (xp – xs) * s2 = ys + yp

Permutation constraints

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

The constraints above are derived from the following EC Affine arithmetic equations:

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
use crate::constraints::ConstraintSystem;
use crate::scalars::ProofEvaluations;

impl<F: FftField + SquareRootField> ConstraintSystem<F>
{
    // endomorphism optimised scalar multiplication constraint quotient poly contribution computation
    pub fn endomul_quot(&self, polys: &WitnessOverDomains<F>, alpha: &[F]) -> Evaluations<F, D<F>>
    {
        if self.emulm.is_zero() {return self.zero4.clone()}

        let xt = &polys.d4.this.w[0];
        let yt = &polys.d4.this.w[1];
        let s1 = &polys.d4.this.w[2];
        let s2 = &polys.d4.this.w[3];
        let b1 = &polys.d4.this.w[4];
        let xs = &polys.d4.next.w[0];
        let ys = &polys.d4.next.w[1];
        let xp = &polys.d4.next.w[2];
        let yp = &polys.d4.next.w[3];
        let b2 = &polys.d4.next.w[4];

        let xq = &(&(&self.l04 + &b2.scale(self.endo - F::one())) * xt);

        let bin_1 = &(b1 - &b1.pow(2));
        let bin_2 = &(b2 - &b2.pow(2));

        // (xp - (1 + (endo - 1) * b2) * xt) * s1 = yp – (2*b1-1)*yt
        let check_1 =
          &(  &(&(xp - xq) * s1)
            - yp)
            + &(yt * &(&b1.scale(F::from(2 as u64)) - &self.l04));

        // s1^2 - s2^2 = (1 + (endo - 1) * b2) * xt - xs
        let check_2 = &(&(&s1.pow(2) - &s2.pow(2)) - xq) + xs;

        // (2*xp + (1 + (endo - 1) * b2) * xt – s1^2) * (s1 + s2) = 2*yp
        let check_3 =
            &(  &(&(&xp.scale(F::from(2 as u64)) + xq) - &s1.pow(2))
              * &(s1 + s2))
          - &yp.scale(F::from(2 as u64));

        // (xp – xs) * s2 = ys + yp
        let check_4 = &(&(&(xp - xs) * s2) - ys) - yp;

        &(&(&(&(&(
            &bin_1.scale(alpha[0])
          + &bin_2.scale(alpha[1]))
          + &check_1.scale(alpha[2]))
          + &check_2.scale(alpha[3]))
          + &check_3.scale(alpha[4]))
          + &check_4.scale(alpha[5]))
        * &self.emull
    }

    pub fn endomul_scalars(evals: &Vec<ProofEvaluations<F>>, endo: F, alpha: &[F]) -> F
    {
        let xt = evals[0].w[0];
        let yt = evals[0].w[1];
        let s1 = evals[0].w[2];
        let s2 = evals[0].w[3];
        let b1 = evals[0].w[4];
        let xs = evals[1].w[0];
        let ys = evals[1].w[1];
        let xp = evals[1].w[2];
        let yp = evals[1].w[3];
        let b2 = evals[1].w[4];

        let xq = (F::one() + &(b2 * &(endo - F::one()))) * &xt;

        let bin_1 = evals[0].w[4] - &evals[0].w[4].square();
        let bin_2 = evals[1].w[4] - &evals[1].w[4].square();

        // (xp - (1 + (endo - 1) * b2) * xt) * s1 = yp – (2*b1-1)*yt
        let check_1 = (xp - xq) * &s1 - &yp + &(yt * &(b1.double() - &F::one()));

        // s1^2 - s2^2 = (1 + (endo - 1) * b2) * xt - xs
        let check_2 = ((s1.square() - &s2.square()) - xq) + &xs;

        // (2*xp + (1 + (endo - 1) * b2) * xt – s1^2) * (s1 + s2) = 2*yp
        let check_3 = ((xp.double() + xq) - &s1.square()) * &(s1 + &s2) - &yp.double();

        // (xp – xs) * s2 = ys + yp
        let check_4 = ((xp - &xs) * &s2) - &ys - &yp;

          bin_1 * &alpha[0]
        + &(bin_2 * &alpha[1])
        + &(check_1 * &alpha[2])
        + &(check_2 * &alpha[3])
        + &(check_3 * &alpha[4])
        + &(check_4 * &alpha[5])
    }

    // endomorphism optimised scalar multiplication constraint linearization poly contribution computation
    pub fn endomul_lnrz(&self, evals: &Vec<ProofEvaluations<F>>, alpha: &[F]) -> DensePolynomial<F>
    {
        self.emulm.scale(Self::endomul_scalars(evals, self.endo, alpha))
    }
}
