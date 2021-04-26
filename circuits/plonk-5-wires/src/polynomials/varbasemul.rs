/*****************************************************************************************************************

This source file implements short Weierstrass curve variable base scalar multiplication custom Plonk polynomials.

Acc := [2]T
for i = n-1 ... 0:
   Q := (r_i == 1) ? T : -T
   Acc := Acc + (Q + Acc)
return (d_0 == 0) ? Q - P : Q

One-bit round constraints:

S = (P + (b ? T : −T)) + P

VBSM gate constraints

    b*(b-1) = 0
    (xp - xt) * s1 = yp – (2b-1)*yt
    s1^2 - s2^2 = xt - xs
    (2*xp + xt – s1^2) * (s1 + s2) = 2*yp
    (xp – xs) * s2 = ys + yp

Permutation constraints

    -> b(i)
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
    s1^2 - s2^2 = xq - xs
    (2*xp + xq – s1^2) * (s1 + s2) = 2*yp
    (xp – xs) * s2 = ys + yp

    *****************************************************************************************************************/

use crate::constraints::CSConstants;
use crate::polynomial::WitnessOverDomains;
use crate::scalars::ProofEvaluations;
use algebra::{FftField, SquareRootField};
use ff_fft::{DensePolynomial, Evaluations, Radix2EvaluationDomain as D};
use oracle::utils::{EvalUtils, PolyUtils};

pub trait CSVbmulGate<F: FftField + SquareRootField>: CSConstants<F> {
    fn mul1m(&self) -> &DensePolynomial<F>; // constraint selector polynomial
    fn mul1l(&self) -> &Evaluations<F, D<F>>; // selector evaluations over domain.d4

    // scalar multiplication constraint quotient poly contribution computation
    fn vbmul_quot(&self, polys: &WitnessOverDomains<F>, alpha: &[F]) -> Evaluations<F, D<F>> {
        if self.mul1m().is_zero() {
            return self.zero4().clone();
        }

        let xt = &polys.d4.this.w[0];
        let yt = &polys.d4.this.w[1];
        let s1 = &polys.d4.this.w[2];
        let s2 = &polys.d4.this.w[3];
        let b = &polys.d4.this.w[4];
        let xs = &polys.d4.next.w[0];
        let ys = &polys.d4.next.w[1];
        let xp = &polys.d4.next.w[2];
        let yp = &polys.d4.next.w[3];

        let bin = &(b - &b.pow(2));

        // (xp - xt) * s1 = yp – (2b-1)*yt
        let check_1 =
            &(&(&(&(xp - xt) * s1) - yp) + &(yt * &(&b.scale(F::from(2 as u64)) - &self.l04())));

        // s1^2 - s2^2 = xt - xs
        let check_2 = &(&(&(&s1.pow(2) - &s2.pow(2)) - xt) + xs);

        // (2*xp + xt – s1^2) * (s1 + s2) = 2*yp
        let check_3 = &(&(&(&xp.scale(F::from(2 as u64)) + xt) - &s1.pow(2)) * &(s1 + s2))
            - &yp.scale(F::from(2 as u64));

        // (xp – xs) * s2 = ys + yp
        let check_4 = &(&(&(xp - xs) * s2) - ys) - &yp;

        &(&(&(&(&bin.scale(alpha[0]) + &check_1.scale(alpha[1])) + &check_2.scale(alpha[2]))
            + &check_3.scale(alpha[3]))
            + &check_4.scale(alpha[4]))
            * &self.mul1l()
    }

    // scalar multiplication constraint linearization poly contribution computation
    fn vbmul_scalars(evals: &Vec<ProofEvaluations<F>>, alpha: &[F]) -> F {
        let xt = evals[0].w[0];
        let yt = evals[0].w[1];
        let s1 = evals[0].w[2];
        let s2 = evals[0].w[3];
        let b = evals[0].w[4];
        let xs = evals[1].w[0];
        let ys = evals[1].w[1];
        let xp = evals[1].w[2];
        let yp = evals[1].w[3];

        let bin = b - &b.square();

        // (xp - xt) * s1 = yp – (2b-1)*yt
        let check_1 = (xp - &xt) * &s1 - &yp + &(yt * &(b.double() - &F::one()));

        // s1^2 - s2^2 = xt - xs
        let check_2 = ((s1.square() - &s2.square()) - &xt) + &xs;

        // (2*xp + xt – s1^2) * (s1 + s2) = 2*yp
        let check_3 = ((xp.double() + &xt) - &s1.square()) * &(s1 + &s2) - &yp.double();

        // (xp – xs) * s2 = ys + yp
        let check_4 = ((xp - &xs) * &s2) - &ys - &yp;

        bin * &alpha[0]
            + &(check_1 * &alpha[1])
            + &(check_2 * &alpha[2])
            + &(check_3 * &alpha[3])
            + &(check_4 * &alpha[4])
    }

    // scalar multiplication constraint linearization poly contribution computation
    fn vbmul_lnrz(&self, evals: &Vec<ProofEvaluations<F>>, alpha: &[F]) -> DensePolynomial<F> {
        self.mul1m().scale(Self::vbmul_scalars(evals, alpha))
    }
}
