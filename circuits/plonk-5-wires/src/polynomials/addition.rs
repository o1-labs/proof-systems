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
        /*
            (x2 - x1) * (y3 + y1) - (y2 - y1) * (x1 - x3)
            (x1 + x2 + x3) * (x1 - x3) * (x1 - x3) - (y3 + y1) * (y3 + y1)
            (x2 - x1) * r = 1
        */
        let y31 = &(&polys.d4.next.w[1] + &polys.d4.this.w[1]);
        let x13 = &(&polys.d4.this.w[0] - &polys.d4.next.w[0]);
        let x21 = &(&polys.d4.this.w[2] - &polys.d4.this.w[0]);

        &(&(&(&(x21 * y31) - &(&(&polys.d4.this.w[3] - &polys.d4.this.w[1]) * x13)).scale(alpha[0])
        +
        &(&(&(&(&polys.d4.this.w[0] + &polys.d4.this.w[2]) + &polys.d4.next.w[0]) * &x13.pow(2)) - &y31.pow(2)).scale(alpha[1]))
        +
        &(&(x21 * &polys.d4.this.w[4]) - &self.l04).scale(alpha[2]))
        *
        &self.addl
    }

    pub fn ecad_scalars(evals: &Vec<ProofEvaluations<F>>, alpha: &[F]) -> F
    {
        let y31 = evals[1].w[1] + &evals[0].w[1];
        let x13 = evals[0].w[0] - &evals[1].w[0];
        let x21 = evals[0].w[2] - &evals[0].w[0];

        ((x21 * y31) - &((evals[0].w[3] - &evals[0].w[1]) * x13)) * &alpha[0] +
        &(((evals[0].w[0] + &evals[0].w[2] + &evals[1].w[0]) * &x13.square() - &y31.square()) * &alpha[1]) +
        &((x21 * &evals[0].w[4] - &F::one()) * &alpha[2])
    }

    // EC Affine addition constraint linearization poly contribution computation
    pub fn ecad_lnrz(&self, evals: &Vec<ProofEvaluations<F>>, alpha: &[F]) -> DensePolynomial<F>
    {
        self.addm.scale(Self::ecad_scalars(evals, alpha))
    }
}
