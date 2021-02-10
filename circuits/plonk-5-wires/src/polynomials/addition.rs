/*****************************************************************************************************************

This source file implements non-special point Weierstrass curve addition constraint polynomials.

    ADD gate constraints

        (x2 - x1) * (y3 + y1) - (y1 - y2) * (x1 - x3)
        (x1 + x2 + x3) * (x1 - x3) * (x1 - x3) - (y3 + y1) * (y3 + y1)
        (x2 - x1) * r = 1

    Permutation constraints

        -> x1
        -> y1
        -> x2
        -> y2
        x3 ->
        y3 ->

    The constraints above are derived from the following EC Affine arithmetic equations:

        (x2 - x1) * s = y2 - y1
        s * s = x1 + x2 + x3
        (x1 - x3) * s = y3 + y1

        =>

        (x2 - x1) * (y3 + y1) = (y1 - y2) * (x1 - x3)
        (x1 + x2 + x3) * (x1 - x3) * (x1 - x3) = (y3 + y1) * (y3 + y1)

*****************************************************************************************************************/

use algebra::{FftField, SquareRootField};
use ff_fft::{Evaluations, DensePolynomial, Radix2EvaluationDomain as D};
use crate::polynomial::WitnessOverDomains;
use oracle::utils::{EvalUtils, PolyUtils};
use crate::constraints::ConstraintSystem;
use crate::scalars::ProofEvaluations;

impl<F: FftField + SquareRootField> ConstraintSystem<F>
{
    // EC Affine addition constraint quotient poly contribution computation
    pub fn ecad_quot(&self, polys: &WitnessOverDomains<F>, alpha: &[F]) -> Evaluations<F, D<F>>
    {
        if self.addm.is_zero() {return self.zero4.clone()}

        let x1 = &polys.d4.this.w[0];
        let y1 = &polys.d4.this.w[1];
        let x2 = &polys.d4.this.w[2];
        let y2 = &polys.d4.this.w[3];
        let x3 = &polys.d4.next.w[0];
        let y3 = &polys.d4.next.w[1];
        let r = &polys.d4.this.w[4];

        let y31 = &(y3 + y1);
        let x13 = &(x1 - x3);
        let x21 = &(x2 - x1);

        /*
            (x2 - x1) * (y3 + y1) - (y2 - y1) * (x1 - x3)
            (x1 + x2 + x3) * (x1 - x3) * (x1 - x3) - (y3 + y1) * (y3 + y1)
            (x2 - x1) * r = 1
        */
        let check_1 = &(&(x21 * y31) - &(&(y2 - y1) * x13));
        let check_2 = &(&(&(&(x1 + x2) + x3) * &x13.pow(2)) - &y31.pow(2));
        let check_3 = &(&(x21 * r) - &self.l04);

        &(&(  &check_1.scale(alpha[0])
            + &check_2.scale(alpha[1]))
            + &check_3.scale(alpha[2]))
        * &self.addl
    }

    pub fn ecad_scalars(evals: &Vec<ProofEvaluations<F>>, alpha: &[F]) -> F
    {
        let x1 = evals[0].w[0];
        let y1 = evals[0].w[1];
        let x2 = evals[0].w[2];
        let y2 = evals[0].w[3];
        let x3 = evals[1].w[0];
        let y3 = evals[1].w[1];
        let r  = evals[0].w[4];

        let y31 = y3 + y1;
        let x13 = x1 - x3;
        let x21 = x2 - x1;

        let check_1 = (x21 * y31) - ((y2 - y1) * x13);
        let check_2 = ((x1 + x2 + x3) * x13.square()) - y31.square();
        let check_3 = (x21 * r) - F::one();

          (check_1 * alpha[0])
        + (check_2 * alpha[1])
        + (check_3 * alpha[2])
    }

    // EC Affine addition constraint linearization poly contribution computation
    pub fn ecad_lnrz(&self, evals: &Vec<ProofEvaluations<F>>, alpha: &[F]) -> DensePolynomial<F>
    {
        self.addm.scale(Self::ecad_scalars(evals, alpha))
    }
}
