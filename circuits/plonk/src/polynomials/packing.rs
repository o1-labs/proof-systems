/*****************************************************************************************************************

This source file implements packing constraint polynomials Plonk primitive.

PACK gate constrains
    si = s1,i + 2*s2,i + 4*s3,i + 8*s4,i + 16*si+1
    s1,i * (s1,i – 1) = 0

*****************************************************************************************************************/

use algebra::{FftField, SquareRootField};
use ff_fft::{Evaluations, DensePolynomial, Radix2EvaluationDomain as D};
use crate::polynomial::WitnessOverDomains;
use oracle::utils::{EvalUtils, PolyUtils};
use crate::constraints::ConstraintSystem;
use crate::scalars::ProofEvaluations;

impl<F: FftField + SquareRootField> ConstraintSystem<F>
{
    // packing constraint quotient poly contribution computation
    pub fn pack_quot(&self, polys: &WitnessOverDomains<F>, alpha: &[F]) -> Evaluations<F, D<F>>
    {
        if self.packm.is_zero() {return self.zero4.clone()}

        &(&(&(&(&(&(&(&(&(&polys.d4.next.w[3] +
            &polys.d4.next.w[2].scale(F::from(2 as u64))) +
            &polys.d4.next.w[1].scale(F::from(4 as u64))) +
            &polys.d4.next.w[0].scale(F::from(8 as u64))) +
            &polys.d4.this.w[4].scale(F::from(16 as u64))) -
            &polys.d4.next.w[4]).scale(alpha[0]) +
        &(&polys.d4.next.w[0] - &polys.d4.next.w[0].pow(2)).scale(alpha[1])) +
        &(&polys.d4.next.w[1] - &polys.d4.next.w[1].pow(2)).scale(alpha[2])) +
        &(&polys.d4.next.w[2] - &polys.d4.next.w[2].pow(2)).scale(alpha[3])) +
        &(&polys.d4.next.w[3] - &polys.d4.next.w[3].pow(2)).scale(alpha[4])) *
        &self.packl
    }

    pub fn pack_scalars(evals: &Vec<ProofEvaluations<F>>, alpha: &[F]) -> F
    {
        ((((((((evals[1].w[3] +
            &evals[1].w[2].double()) +
            &evals[1].w[1].double().double()) +
            &evals[1].w[0].double().double().double()) +
            &evals[0].w[4].double().double().double().double()) -
            &evals[1].w[4]) * &alpha[0] +
        &((evals[1].w[0] - &evals[1].w[0].square()) * &alpha[1])) +
        &((evals[1].w[1] - &evals[1].w[1].square()) * &alpha[2])) +
        &((evals[1].w[2] - &evals[1].w[2].square()) * &alpha[3])) +
        &((evals[1].w[3] - &evals[1].w[3].square()) * &alpha[4])
    }

    // packing constraint linearization poly contribution computation
    pub fn pack_lnrz(&self, evals: &Vec<ProofEvaluations<F>>, alpha: &[F]) -> DensePolynomial<F>
    {
        self.packm.scale(Self::pack_scalars(evals, alpha))
    }
}
