/*****************************************************************************************************************

This source file implements constraint polynomials for non-special point doubling on Weierstrass curve

DOUBLE gate constrains

    4 * y1^2 * (x2 + 2*x1) = 9 * x1^4
    2 * y1 * (y2 - y1) = (3 * x1^2) * (x2 – x1)
    y1 * r = 1

Permutation constrains

    -> x1
    -> y1
    x2 ->
    y2 ->

The constrains above are derived from the following EC Affine arithmetic equations:

    2 * s * y1 = 3 * x1^2
    x2 = s^2 – 2*x1
    y2 = y1 + s * (x2 – x1)

    =>

    2 * s * y1 = 3 * x1^2
    x2 = s^2 – 2*x1
    2 * y1 * (y2 - y1) = 3 * x1^2 * (x2 – x1)

    =>

    4 * y1^2 * (x2 + 2*x1) = 9 * x1^4
    2 * y1 * (y2 - y1) = 3 * x1^2 * (x2 – x1)

*****************************************************************************************************************/

use crate::constraints::ConstraintSystem;
use crate::polynomial::WitnessOverDomains;
use crate::scalars::ProofEvaluations;
use ark_ff::{FftField, SquareRootField, Zero};
use ark_poly::{univariate::DensePolynomial, Evaluations, Radix2EvaluationDomain as D};
use oracle::utils::{EvalUtils, PolyUtils};

impl<F: FftField + SquareRootField> ConstraintSystem<F> {
    // EC Affine doubling constraint quotient poly contribution computation
    pub fn double_quot(&self, polys: &WitnessOverDomains<F>, alpha: &[F]) -> Evaluations<F, D<F>> {
        if self.doublem.is_zero() {
            return self.doublel.clone();
        }

        &(&(&(&(&polys.d8.this.w[1].pow(2).scale(F::from(4 as u64))
            * &(&polys.d8.this.w[2] + &polys.d8.this.w[0].scale(F::from(2 as u64))))
            - &polys.d8.this.w[0].pow(4).scale(F::from(9 as u64)))
            .scale(alpha[0])
            + &(&(&polys.d8.this.w[1].scale(F::from(2 as u64))
                * &(&polys.d8.this.w[3] + &polys.d8.this.w[1]))
                - &(&(&polys.d8.this.w[0] - &polys.d8.this.w[2])
                    * &polys.d8.this.w[0].pow(2).scale(F::from(3 as u64))))
                .scale(alpha[1]))
            + &(&(&polys.d8.this.w[1] * &polys.d8.this.w[4]) - &self.l08).scale(alpha[2]))
            * &self.doublel
    }

    pub fn double_scalars(evals: &Vec<ProofEvaluations<F>>, alpha: &[F]) -> F {
        (((evals[0].w[1].square()
            * &F::from(4 as u64)
            * &(evals[0].w[2] + &evals[0].w[0].double()))
            - &(evals[0].w[0].square().square() * &F::from(9 as u64)))
            * &alpha[0])
            + &(((evals[0].w[1].double() * &(evals[0].w[3] + &evals[0].w[1]))
                - &((evals[0].w[0] - &evals[0].w[2])
                    * &evals[0].w[0].square()
                    * &F::from(3 as u64)))
                * &alpha[1])
            + &((evals[0].w[1] * &evals[0].w[4] - &F::one()) * &alpha[2])
    }

    // EC Affine doubling constraint linearization poly contribution computation
    pub fn double_lnrz(&self, evals: &Vec<ProofEvaluations<F>>, alpha: &[F]) -> DensePolynomial<F> {
        self.doublem.scale(Self::double_scalars(evals, alpha))
    }
}
