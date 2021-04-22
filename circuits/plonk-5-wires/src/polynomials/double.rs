/*****************************************************************************************************************

This source file implements constraint polynomials for non-special point doubling on Weierstrass curve

DOUBLE gate constraints

    4 * y1^2 * (x2 + 2*x1) = 9 * x1^4
    2 * y1 * (y2 - y1) = (3 * x1^2) * (x2 – x1)
    y1 * r = 1

Permutation constraints

    -> x1
    -> y1
    x2 ->
    y2 ->

The constraints above are derived from the following EC Affine arithmetic equations:

    2 * s * y1 = 3 * x1^2
    x2 = s^2 – 2*x1
    y2 = s * (x1 – x2) - y1

    =>

    2 * s * y1 = 3 * x1^2
    x2 = s^2 – 2*x1
    2 * y1 * (y2 + y1) = 3 * x1^2 * (x1 – x2)

    =>

    4 * y1^2 * (x2 + 2*x1) = 9 * x1^4
    2 * y1 * (y2 + y1) = 3 * x1^2 * (x1 – x2)

*****************************************************************************************************************/

use algebra::{FftField, SquareRootField};
use ff_fft::{Evaluations, DensePolynomial, Radix2EvaluationDomain as D};
use crate::polynomial::WitnessOverDomains;
use oracle::utils::{EvalUtils, PolyUtils};
use crate::constraints::ConstraintSystem;
use crate::scalars::ProofEvaluations;

impl<F: FftField + SquareRootField> ConstraintSystem<F>
{
    // EC Affine doubling constraint quotient poly contribution computation
    pub fn double_quot(&self, polys: &WitnessOverDomains<F>, alpha: &[F]) -> Evaluations<F, D<F>>
    {
        if self.doublem.is_zero() {return self.doublel.clone()}

        let x1 = &polys.d8.this.w[0];
        let y1 = &polys.d8.this.w[1];
        let x2 = &polys.d8.this.w[2];
        let y2 = &polys.d8.this.w[3];
        let y1_inv  = &polys.d8.this.w[4];

        let check_1 =
            &(  &y1.pow(2).scale(F::from(4 as u64))
              * &(x2 + &x1.scale(F::from(2 as u64))))
          - &x1.pow(4).scale(F::from(9 as u64));

        let check_2 =
            &(  &y1.scale(F::from(2 as u64))
              * &(y2 + y1))
          - &(  &(x1 - x2)
              * &x1.pow(2).scale(F::from(3 as u64)));

        let check_3 = &(y1 * &y1_inv) - &self.l08;

        &(&(  &check_1.scale(alpha[0])
            + &check_2.scale(alpha[1]))
            + &check_3.scale(alpha[2]))
        * &self.doublel
    }

    pub fn double_scalars(evals: &Vec<ProofEvaluations<F>>, alpha: &[F]) -> F
    {
        let x1 = evals[0].w[0];
        let y1 = evals[0].w[1];
        let x2 = evals[0].w[2];
        let y2 = evals[0].w[3];
        let y1_inv = evals[0].w[4];

        let check_1 =
            (  y1.square() * &F::from(4 as u64)
             * &(x2 + &x1.double()))
          - &(x1.square().square() * &F::from(9 as u64));

        let check_2 =
            (y1.double() * &(y2 + &y1))
          - &((x1 - &x2) * &x1.square() * &F::from(3 as u64));

        let check_3 = y1 * &y1_inv - &F::one();

          (check_1 * &alpha[0])
        + &(check_2 * &alpha[1])
        + &(check_3 * &alpha[2])
    }

    // EC Affine doubling constraint linearization poly contribution computation
    pub fn double_lnrz(&self, evals: &Vec<ProofEvaluations<F>>, alpha: &[F]) -> DensePolynomial<F>
    {
        self.doublem.scale(Self::double_scalars(evals, alpha))
    }
}
