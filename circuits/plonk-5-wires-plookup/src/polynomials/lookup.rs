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
    w4 = w0 + w1*(2^8) + w2*(2^16) + w3*(2^24)

*****************************************************************************************************************/

use crate::constraints::ConstraintSystem;
use crate::polynomial::WitnessOverDomains;
use crate::scalars::ProofEvaluations;
use algebra::{FftField, SquareRootField};
use ff_fft::{DensePolynomial, Evaluations, Radix2EvaluationDomain as D};
use oracle::utils::{EvalUtils, PolyUtils};

impl<F: FftField + SquareRootField> ConstraintSystem<F> {
    // lookup constraint quotient poly contribution computation
    pub fn lookup_quot(&self, polys: &WitnessOverDomains<F>, alpha: &[F]) -> Evaluations<F, D<F>> {
        if self.lkpm.is_zero() {
            return self.zero4.clone();
        }

        &(&(&(&(&polys.d4.this.w[0] + &polys.d4.this.w[1].scale(F::from(0x100 as u64)))
            + &polys.d4.this.w[2].scale(F::from(0x10000 as u64)))
            + &polys.d4.this.w[3].scale(F::from(0x1000000 as u64)))
            - &polys.d4.this.w[4])
            .scale(alpha[0])
            * &self.lkpl4
    }

    pub fn lookup_scalars(evals: &Vec<ProofEvaluations<F>>, alpha: &[F]) -> F {
        (evals[0].w[0] - &evals[0].w[4]
            + &(evals[0].w[1] * &F::from(0x100 as u64))
            + &(evals[0].w[2] * &F::from(0x10000 as u64))
            + &(evals[0].w[3] * &F::from(0x1000000 as u64)))
            * &alpha[0]
    }

    // lookup constraint linearization poly contribution computation
    pub fn lookup_lnrz(&self, evals: &Vec<ProofEvaluations<F>>, alpha: &[F]) -> DensePolynomial<F> {
        self.lkpm.scale(Self::lookup_scalars(evals, alpha))
    }
}
