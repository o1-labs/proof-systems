/*****************************************************************************************************************

This source file implements short Weierstrass curve variable base scalar multiplication custom Plonk polynomials.

Acc := [2]T
for i = n-1 ... 0:
   Q := (r_i == 1) ? T : -T
   Acc := Acc + (Q + Acc)
return (d_0 == 0) ? Q - P : Q

One-bit round constraints:

S = (P + (b ? T : −T)) + P

VBSM gate constrains

    b*(b-1) = 0
    (xp - xt) * s1 = yp – (2b-1)*yt
    s1^2 - s2^2 = xt - xs
    (2*xp + xt – s1^2) * (s1 + s2) = 2*yp
    (xp – xs) * s2 = ys + yp

Permutation constrains

    -> b(i)
    -> xt(i) -> xt(i+2) -> … -> xt(509)
    -> yt(i) -> yt(i+2) -> … -> yt(509)
    -> xp(i)
    -> xp(i+2) -> xs(i) ->
    -> yp(i)
    -> yp(i+2) -> ys(i) ->
    xs(509) ->
    ys(509) ->

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
use crate::constraints::ConstraintSystem;
use crate::scalars::ProofEvaluations;

impl<F: FftField + SquareRootField> ConstraintSystem<F>
{
    // scalar multiplication constraint quotient poly contribution computation
    pub fn vbmul_quot(&self, polys: &WitnessOverDomains<F>, alpha: &[F]) -> Evaluations<F, D<F>>
    {
        if self.mul1m.is_zero() {return self.zero4.clone()}
    
        // verify booleanity of the scalar bits
        &(&(&(&(&(&polys.d4.this.w[4] - &polys.d4.this.w[4].pow(2)).scale(alpha[0])
        +
        // (xp - xt) * s1 = yp – (2b-1)*yt
        &(&(&(&(&polys.d4.next.w[2] - &polys.d4.this.w[0]) * &polys.d4.this.w[2]) - &polys.d4.next.w[3]) +
            &(&polys.d4.this.w[1] * &(&polys.d4.this.w[4].scale(F::from(2 as u64)) - &self.l04))).scale(alpha[1]))
        +
        // s1^2 - s2^2 = xt - xs
        &(&(&(&polys.d4.this.w[2].pow(2) - &polys.d4.this.w[3].pow(2)) -
            &polys.d4.this.w[0]) + &polys.d4.next.w[0]).scale(alpha[2]))
        +
        // (2*xp + xt – s1^2) * (s1 + s2) = 2*yp
        &(&(&(&(&polys.d4.next.w[2].scale(F::from(2 as u64)) + &polys.d4.this.w[0]) - &polys.d4.this.w[2].pow(2)) *
            &(&polys.d4.this.w[2] + &polys.d4.this.w[3])) - &polys.d4.next.w[3].scale(F::from(2 as u64))).scale(alpha[3]))
        +
        // (xp – xs) * s2 = ys + yp
        &(&(&(&(&polys.d4.next.w[2] - &polys.d4.next.w[0]) * &polys.d4.this.w[3]) -
            &polys.d4.next.w[1]) - &polys.d4.next.w[3]).scale(alpha[4]))
        *
        &self.mul1l
    }

    // scalar multiplication constraint linearization poly contribution computation
    pub fn vbmul_scalars(evals: &Vec<ProofEvaluations<F>>, alpha: &[F]) -> F
    {
        // verify booleanity of the scalar bits
        (evals[0].w[4] - &evals[0].w[4].square()) * &alpha[0]
        +
        // (xp - xt) * s1 = yp – (2b-1)*yt
        &(((evals[1].w[2] - &evals[0].w[0]) * &evals[0].w[2] - &evals[1].w[3] +
            &(evals[0].w[1] * &(evals[0].w[4].double() - &F::one()))) * &alpha[1])
        +
        // s1^2 - s2^2 = xt - xs
        &((((evals[0].w[2].square() - &evals[0].w[3].square()) - &evals[0].w[0]) + &evals[1].w[0]) * &alpha[2])
        +
        // (2*xp + xt – s1^2) * (s1 + s2) = 2*yp
        &((((evals[1].w[2].double() + &evals[0].w[0]) - &evals[0].w[2].square()) *
            &(evals[0].w[2] + &evals[0].w[3]) - &evals[1].w[3].double()) * &alpha[3])
        +
        // (xp – xs) * s2 = ys + yp
        &((((evals[1].w[2] - &evals[1].w[0]) * &evals[0].w[3]) -
            &evals[1].w[1] - &evals[1].w[3]) * &alpha[4])
    }

    // scalar multiplication constraint linearization poly contribution computation
    pub fn vbmul_lnrz(&self, evals: &Vec<ProofEvaluations<F>>, alpha: &[F]) -> DensePolynomial<F>
    {
        self.mul1m.scale(Self::vbmul_scalars(evals, alpha))
    }
}
