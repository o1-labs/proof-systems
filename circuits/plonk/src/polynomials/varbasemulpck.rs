/*****************************************************************************************************************

This source file implements short Weierstrass curve variable base
scalar multiplication with packing custom Plonk constraint polynomials

Acc := [2]T
for i = n-1 ... 0:
   Q := (r_i == 1) ? T : -T
   Acc := Acc + (Q + Acc)
return (d_0 == 0) ? Q - P : Q

One-bit round constraints:

S = (P + (b ? T : −T)) + P

VBSMPACK gate constrains

    b*(b-1) = 0
    (xp - xt) * s1 = yp – (2b-1)*yt
    (2*xp – s1^2 + xt) * ((xp – xs) * s1 + ys + yp) = (xp – xs) * 2*yp
    (ys + yp)^2 = (xp – xs)^2 * (s1^2 – xt + xs)
    n1 = 2*n2 + b

GENERIC gate constrains
    n2 = 0

Permutation constrains
    n2(i+1) -> n1(i+2)
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
    (2*xp – s1^2 + xq) * (s1 + s2) = 2*yp
    s2^2 = s1^2 - xq + xs
    (xp – xs) * s2 = ys + yp

    =>

    (xq - xp) * s1 = yq - yp
    (2*xp – s1^2 + xq) * ((xp – xs) * s1 + ys + yp) = (xp – xs) * 2*yp
    (ys + yp)^2 = (xp – xs)^2 * (s1^2 – xq + xs)

*****************************************************************************************************************/

use algebra::{FftField, SquareRootField};
use ff_fft::{Evaluations, DensePolynomial, Radix2EvaluationDomain as D};
use crate::polynomial::WitnessOverDomains;
use oracle::utils::{EvalUtils, PolyUtils};
use crate::constraints::ConstraintSystem;
use crate::scalars::ProofEvaluations;

impl<F: FftField + SquareRootField> ConstraintSystem<F>
{
    // scalar multiplication with packing constraint quotient poly contribution computation
    pub fn vbmulpck_quot(&self, polys: &WitnessOverDomains<F>, alpha: &[F]) -> Evaluations<F, D<F>>
    {
        if self.mul2m.is_zero() {return self.zero8.clone()}
        let ps = &(&polys.d8.next.w[2] - &polys.d8.next.w[0]);

        // verify booleanity of the scalar bits
        &(&(&(&(&(&polys.d8.this.w[3] - &polys.d8.this.w[3].pow(2)).scale(alpha[0])
        +
        // (xp - xt) * s1 = yp – (2b-1)*yt
        &(&(&(&(&polys.d8.next.w[2] - &polys.d8.this.w[0]) * &polys.d8.this.w[2]) - &polys.d8.next.w[3]) +
            &(&polys.d8.this.w[1] * &(&polys.d8.this.w[3].scale(F::from(2 as u64)) - &self.l04))).scale(alpha[1]))
        +
        // (2*xp – s1^2 + xt) * ((xp – xs) * s1 + ys + yp) = (xp – xs) * 2*yp
        &(&(&(&(&polys.d8.next.w[2].scale(F::from(2 as u64)) - &polys.d8.this.w[2].pow(2)) + &polys.d8.this.w[0]) *
            &(&(&(ps * &polys.d8.this.w[2]) + &polys.d8.next.w[1]) + &polys.d8.next.w[3])) -
            &(&polys.d8.next.w[3].scale(F::from(2 as u64)) * ps)).scale(alpha[2]))
        +
        // (ys + yp)^2 - (xp – xs)^2 * (s1^2 – xt + xs)
        &(&(&polys.d8.next.w[1] + &polys.d8.next.w[3]).pow(2) - &(&ps.pow(2) *
            &(&(&polys.d8.this.w[2].pow(2) - &polys.d8.this.w[0]) + &polys.d8.next.w[0]))).scale(alpha[3]))
        +
        // n1 - 2*n2 + b
        &(&(&polys.d8.this.w[4] - &polys.d8.next.w[4].scale(F::from(2 as u64))) + &polys.d8.this.w[3]).scale(alpha[4]))
        *
        &self.mul2l
    }

    // scalar multiplication with packing constraint linearization poly contribution computation
    pub fn vbmulpck_scalars(evals: &Vec<ProofEvaluations<F>>, alpha: &[F]) -> F
    {
        let ps = evals[1].w[2] - &evals[1].w[0];

        // verify booleanity of the scalar bits
        (evals[0].w[3] - &evals[0].w[3].square()) * &alpha[0]
        +
        // (xp - xt) * s1 = yp – (2b-1)*yt
        &(((((evals[1].w[2] - &evals[0].w[0]) * &evals[0].w[2]) - &evals[1].w[3]) +
            &(evals[0].w[1] * &(evals[0].w[3] * &F::from(2 as u64) - &F::one()))) * &alpha[1])
        +
        // (2*xp – s1^2 + xt) * ((xp – xs) * s1 + ys + yp) = (xp – xs) * 2*yp
        &(((((evals[1].w[2] * &F::from(2 as u64) - &evals[0].w[2].square()) + &evals[0].w[0]) *
            &(((ps * &evals[0].w[2]) + &evals[1].w[1]) + &evals[1].w[3])) -
            &(evals[1].w[3] * &F::from(2 as u64) * ps)) * &alpha[2])
        +
        // (ys + yp)^2 - (xp – xs)^2 * (s1^2 – xt + xs)
        &(((evals[1].w[1] + &evals[1].w[3]).square() - &(ps.square() *
            &((evals[0].w[2].square() - &evals[0].w[0]) + &evals[1].w[0]))) * &alpha[3])
        +
        // n1 - 2*n2 + b
        &(((evals[0].w[4] - &(evals[1].w[4] * &F::from(2 as u64))) + &evals[0].w[3]) * &alpha[4])
    }

    // scalar multiplication with packing constraint linearization poly contribution computation
    pub fn vbmulpck_lnrz(&self, evals: &Vec<ProofEvaluations<F>>, alpha: &[F]) -> DensePolynomial<F>
    {
        self.mul2m.scale(Self::vbmulpck_scalars(evals, alpha))
    }
}
