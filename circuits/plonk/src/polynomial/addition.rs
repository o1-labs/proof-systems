/*****************************************************************************************************************

This source file implements non-special point Weierstrass curve addition

    (x2 - x1) * s = y2 - y1
    s * s = x1 + x2 + x3
    (x1 - x3) * s = y3 + y1

constraint polynomials.

    (x2 - x1) * (y3 + y1) - (y1 - y2) * (x1 - x3)
    (x1 + x2 + x3) * (x1 - x3) * (x1 - x3) - (y3 + y1) * (y3 + y1)

1. First gate constrains the point addition
2. Second gate constrains the abscissas distinctness check

Constraint equations on wires l, r, o, l_next, r_next, o_next where
    l=y1, r=y2, o=y3, l_next=x1, r_next=x2, o_next=x3:

    (r_next - l_next) * (o + l) - (l - r) * (l_next - o_next) = 0
    (l_next + r_next + o_next) * (l_next - o_next) * (l_next - o_next) - (o + l) * (o + l) = 0

*****************************************************************************************************************/

use algebra::{FftField, SquareRootField};
use ff_fft::{Evaluations, DensePolynomial, Radix2EvaluationDomain as D};
use crate::polynomials::WitnessOverDomains;
use oracle::utils::{EvalUtils, PolyUtils};
use crate::constraints::ConstraintSystem;
use crate::scalars::ProofEvaluations;

impl<F: FftField + SquareRootField> ConstraintSystem<F> 
{
    // EC Affine addition constraint quotient poly contribution computation
    pub fn ecad_quot(&self, polys: &WitnessOverDomains<F>, alpha: &Vec<F>) -> (Evaluations<F, D<F>>, Evaluations<F, D<F>>)
    {
        /*
            (r_next - l_next) * (o + l) - (l - r) * (l_next - o_next) = 0
            (l_next + r_next + o_next) * (l_next - o_next) * (l_next - o_next) - (o + l) * (o + l) = 0
        */
        let ylo = &(&polys.d2.this.l + &polys.d2.this.o);
        let xlo = &(&polys.d4.next.l - &polys.d4.next.o);

        (
            &(&Evaluations::multiply
            (
                &[&(&polys.d2.next.r - &polys.d2.next.l), ylo, &self.addl3], self.domain.d2
            )
            -
            &Evaluations::multiply
            (
                &[&(&polys.d2.next.l - &polys.d2.next.o), &(&polys.d2.this.r - &polys.d2.this.l), &self.addl3], self.domain.d2
            )).scale(alpha[4])
            -
            &Evaluations::multiply
            (
                &[ylo, ylo, &self.addl3], self.domain.d2
            ).scale(alpha[5])
            ,
            Evaluations::multiply
            (
                &[&(&polys.d4.next.l + &(&polys.d4.next.r + &polys.d4.next.o)), xlo, xlo, &self.addl4], self.domain.d4
            ).scale(alpha[5])
        )
    }

    // EC Affine addition constraint linearization poly contribution computation
    pub fn ecad_lnrz(&self, evals: &Vec<ProofEvaluations<F>>, alpha: &Vec<F>) -> DensePolynomial<F>
    {
        self.addm.scale
        (
            ((evals[1].r - &evals[1].l) * &(evals[0].o + &evals[0].l) -
            &((evals[1].l - &evals[1].o) * &(evals[0].r - &evals[0].l))) * &alpha[4] +
            &(((evals[1].l + &evals[1].r + &evals[1].o) * &(evals[1].l - &evals[1].o) * &(evals[1].l - &evals[1].o) -
            &((evals[0].o + &evals[0].l) * &(evals[0].o + &evals[0].l))) * &alpha[5])
        )
    }
}
