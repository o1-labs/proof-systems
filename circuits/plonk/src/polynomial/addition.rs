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
        let ylo = &(&polys.d4.this.l + &polys.d4.this.o);
        let xlo = &(&polys.d8.next.l - &polys.d8.next.o);

        (
            &(&(&(&(&polys.d4.next.r - &polys.d4.next.l) * ylo)
            -
            &(&(&polys.d4.next.l - &polys.d4.next.o) * &(&polys.d4.this.r - &polys.d4.this.l))).scale(alpha[1])
            -
            &(ylo * ylo).scale(alpha[2]))
            *
            &self.addl3
            ,
            (&(&(&polys.d8.next.l + &(&polys.d8.next.r + &polys.d8.next.o)) * &(xlo * xlo)) * &self.addl4).scale(alpha[2])
        )
    }

    pub fn ecad_scalars(evals: &Vec<ProofEvaluations<F>>, alpha: &Vec<F>) -> Vec<F>
    {
        vec!
        [
            ((evals[1].r - &evals[1].l) * &(evals[0].o + &evals[0].l) -
            &((evals[1].l - &evals[1].o) * &(evals[0].r - &evals[0].l))) * &alpha[1] +
            &(((evals[1].l + &evals[1].r + &evals[1].o) * &(evals[1].l - &evals[1].o) * &(evals[1].l - &evals[1].o) -
            &((evals[0].o + &evals[0].l) * &(evals[0].o + &evals[0].l))) * &alpha[2])
        ]
    }

    // EC Affine addition constraint linearization poly contribution computation
    pub fn ecad_lnrz(&self, evals: &Vec<ProofEvaluations<F>>, alpha: &Vec<F>) -> DensePolynomial<F>
    {
        self.addm.scale(Self::ecad_scalars(evals, alpha)[0])
    }
}
