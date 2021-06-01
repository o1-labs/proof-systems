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

VBSMPACK gate constraints

    b*(b-1) = 0
    (xp - xt) * s1 = yp – (2b-1)*yt
    (2*xp – s1^2 + xt) * ((xp – xs) * s1 + ys + yp) = (xp – xs) * 2*yp
    (ys + yp)^2 = (xp – xs)^2 * (s1^2 – xt + xs)
    n1 = 2*n2 + b

GENERIC gate constraints
    n2 = 0

Permutation constraints
    n2(i+1) -> n1(i+2)
    -> xt(i) -> xt(i+2) -> … -> xt(509)
    -> yt(i) -> yt(i+2) -> … -> yt(509)
    -> xp(i)
    -> xp(i+2) -> xs(i) ->
    -> yp(i)
    -> yp(i+2) -> ys(i) ->
    xs(509) ->
    ys(509) ->

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
    (2*xp – s1^2 + xq) * (s1 + s2) = 2*yp
    s2^2 = s1^2 - xq + xs
    (xp – xs) * s2 = ys + yp

    =>

    (xq - xp) * s1 = yq - yp
    (2*xp – s1^2 + xq) * ((xp – xs) * s1 + ys + yp) = (xp – xs) * 2*yp
    (ys + yp)^2 = (xp – xs)^2 * (s1^2 – xq + xs)

*****************************************************************************************************************/

use crate::constraints::ConstraintSystem;
use crate::polynomial::WitnessOverDomains;
use crate::scalars::ProofEvaluations;
use ark_ff::{FftField, SquareRootField};
use ark_poly::{DensePolynomial, Evaluations, Radix2EvaluationDomain as D};
use oracle::utils::{EvalUtils, PolyUtils};

impl<F: FftField + SquareRootField> ConstraintSystem<F> {
    // scalar multiplication with packing constraint quotient poly contribution computation
    pub fn vbmulpck_quot(
        &self,
        polys: &WitnessOverDomains<F>,
        alpha: &[F],
    ) -> Evaluations<F, D<F>> {
        if self.mul2m.is_zero() {
            return self.zero8.clone();
        }

        let xt = &polys.d8.this.w[0];
        let yt = &polys.d8.this.w[1];
        let s1 = &polys.d8.this.w[2];
        let b = &polys.d8.this.w[3];
        let n1 = &polys.d8.this.w[4];
        let xs = &polys.d8.next.w[0];
        let ys = &polys.d8.next.w[1];
        let xp = &polys.d8.next.w[2];
        let yp = &polys.d8.next.w[3];
        let n2 = &polys.d8.next.w[4];

        let ps = &(xp - xs);

        let bin = &(b - &b.pow(2));

        // (xp - xt) * s1 = yp – (2b-1)*yt
        let check_1 =
            &(&(&(&(xp - xt) * s1) - &yp) + &(yt * &(&b.scale(F::from(2 as u64)) - &self.l08)));

        // (2*xp – s1^2 + xt) * ((xp – xs) * s1 + ys + yp) = (xp – xs) * 2*yp
        let check_2 = &(&(&(&(&xp.scale(F::from(2 as u64)) - &s1.pow(2)) + xt)
            * &(&(&(ps * s1) + ys) + yp))
            - &(&yp.scale(F::from(2 as u64)) * ps));

        // (ys + yp)^2 - (xp – xs)^2 * (s1^2 – xt + xs)
        let check_3 = &(&(ys + yp).pow(2) - &(&ps.pow(2) * &(&(&s1.pow(2) - xt) + xs)));

        // n1 - 2*n2 - b
        let check_4 = &(&(n1 - &n2.scale(F::from(2 as u64))) - &b);

        &(&(&(&(&bin.scale(alpha[0]) + &check_1.scale(alpha[1])) + &check_2.scale(alpha[2]))
            + &check_3.scale(alpha[3]))
            + &check_4.scale(alpha[4]))
            * &self.mul2l
    }

    // scalar multiplication with packing constraint linearization poly contribution computation
    pub fn vbmulpck_scalars(evals: &Vec<ProofEvaluations<F>>, alpha: &[F]) -> F {
        let xt = evals[0].w[0];
        let yt = evals[0].w[1];
        let s1 = evals[0].w[2];
        let b = evals[0].w[3];
        let n1 = evals[0].w[4];
        let xs = evals[1].w[0];
        let ys = evals[1].w[1];
        let xp = evals[1].w[2];
        let yp = evals[1].w[3];
        let n2 = evals[1].w[4];

        let ps = xp - &xs;

        let bin = b - &b.square();

        // (xp - xt) * s1 = yp – (2b-1)*yt
        let check_1 = (((xp - &xt) * &s1) - &yp) + &(yt * &(b.double() - &F::one()));

        // (2*xp – s1^2 + xt) * ((xp – xs) * s1 + ys + yp) = (xp – xs) * 2*yp
        let check_2 = (((xp.double() - &s1.square()) + &xt) * &(((ps * &s1) + &ys) + &yp))
            - &(yp.double() * ps);

        // (ys + yp)^2 - (xp – xs)^2 * (s1^2 – xt + xs)
        let check_3 = (ys + &yp).square() - &(ps.square() * &(s1.square() - &xt + &xs));

        // n1 - 2*n2 - b
        let check_4 = (n1 - &(n2.double())) - &b;

        bin * &alpha[0]
            + &(check_1 * &alpha[1])
            + &(check_2 * &alpha[2])
            + &(check_3 * &alpha[3])
            + &(check_4 * &alpha[4])
    }

    // scalar multiplication with packing constraint linearization poly contribution computation
    pub fn vbmulpck_lnrz(
        &self,
        evals: &Vec<ProofEvaluations<F>>,
        alpha: &[F],
    ) -> DensePolynomial<F> {
        self.mul2m.scale(Self::vbmulpck_scalars(evals, alpha))
    }
}
