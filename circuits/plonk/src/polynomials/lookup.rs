/*****************************************************************************************************************

This source file implements lookup constraint gate Plonk primitive.

The wires are:

0. function opcode (always 4 bits)
1. output
2. input
3. input
4. lookup value

Lookup gate constrains:

XOR8:
    w0 = 0x0001
    w4 = w0 + w1*(2^4) + w2*(2^12) + w3*(2^20) 

*****************************************************************************************************************/

use algebra::{FftField, SquareRootField};
use ff_fft::{Evaluations, DensePolynomial, Radix2EvaluationDomain as D};
use crate::polynomial::WitnessOverDomains;
use oracle::utils::{EvalUtils, PolyUtils};
use crate::constraints::ConstraintSystem;
use crate::scalars::ProofEvaluations;

impl<F: FftField + SquareRootField> ConstraintSystem<F>
{
    // lookup constraint quotient poly contribution computation
    pub fn lookup_quot(&self, polys: &WitnessOverDomains<F>, alpha: &[F]) -> (Evaluations<F, D<F>>, Evaluations<F, D<F>>)
    {
        if self.lkpm.is_zero() {return (self.zero4.clone(), self.zero8.clone())}

        (
            &(&(&(&(&polys.d4.this.w[0] +
                &polys.d4.this.w[1].scale(F::from(16 as u64))) +
                &polys.d4.this.w[2].scale(F::from(4096 as u64))) +
                &polys.d4.this.w[3].scale(F::from(1048576 as u64))) -
                &polys.d4.this.w[4]).scale(alpha[0]) * &self.lkpl4
            ,
            (1..8).fold(self.lkpl8.scale(alpha[1]), |x, i|
                &x * &(&polys.d8.this.w[0] - &self.l08.scale(F::from(i as u64))))
        )
    }

    pub fn lookup_scalars(evals: &Vec<ProofEvaluations<F>>, alpha: &[F]) -> F
    {
        (evals[0].w[0] - &evals[0].w[4] +
            &(evals[0].w[1] * &F::from(16 as u64)) +
            &(evals[0].w[2] * &F::from(4096 as u64)) +
            &(evals[0].w[3] * &F::from(1048576 as u64))) *
            &alpha[0]
        +
        &(1..8).fold(alpha[1], |x, i| x * &(evals[0].w[0] - &F::from(i as u64)))
    }

    // lookup constraint linearization poly contribution computation
    pub fn lookup_lnrz(&self, evals: &Vec<ProofEvaluations<F>>, alpha: &[F]) -> DensePolynomial<F>
    {
        self.lkpm.scale(Self::lookup_scalars(evals, alpha))
    }
}
