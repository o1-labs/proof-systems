/*****************************************************************************************************************

This source file implements packing constraint polynomials Plonk primitive.

PACK gate constraints
    s = s_0 + 2*s_1 + 4*s_2 + 8*s_3 + 16*s_4

    s_i * (s_i - 1) = 0
      for 0 <= i <= 3

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

        let b_0 = &polys.d4.next.w[3];
        let b_1 = &polys.d4.next.w[2];
        let b_2 = &polys.d4.next.w[1];
        let b_3 = &polys.d4.next.w[0];
        let b_4 = &polys.d4.this.w[4];
        let res = &polys.d4.next.w[4];

        let unpack =
          &(&(&(&(&(  b_0
                    + &b_1.scale(F::from(2 as u64)))
                    + &b_2.scale(F::from(4 as u64)))
                    + &b_3.scale(F::from(8 as u64)))
                    + &b_4.scale(F::from(16 as u64)))
                    - res);

        let bin_3 = &(b_3 - &b_3.pow(2));
        let bin_2 = &(b_2 - &b_2.pow(2));
        let bin_1 = &(b_1 - &b_1.pow(2));
        let bin_0 = &(b_0 - &b_0.pow(2));

        &(&(&(&(  &unpack.scale(alpha[0])
                + &bin_3.scale(alpha[1]))
                + &bin_2.scale(alpha[2]))
                + &bin_1.scale(alpha[3]))
                + &bin_0.scale(alpha[4]))
        * &self.packl
    }

    pub fn pack_scalars(evals: &Vec<ProofEvaluations<F>>, alpha: &[F]) -> F
    {
        let b_0 = evals[1].w[3];
        let b_1 = evals[1].w[2];
        let b_2 = evals[1].w[1];
        let b_3 = evals[1].w[0];
        let b_4 = evals[0].w[4];
        let res = evals[1].w[4];

        let unpack =
            b_0
          + b_1.double()
          + b_2.double().double()
          + b_3.double().double().double()
          + b_4.double().double().double().double()
          - res;

        let bin_3 = b_3 - b_3.square();
        let bin_2 = b_2 - b_2.square();
        let bin_1 = b_1 - b_1.square();
        let bin_0 = b_0 - b_0.square();

          unpack * alpha[0]
        + bin_3 * alpha[1]
        + bin_2 * alpha[2]
        + bin_1 * alpha[3]
        + bin_0 * alpha[4]
    }

    // packing constraint linearization poly contribution computation
    pub fn pack_lnrz(&self, evals: &Vec<ProofEvaluations<F>>, alpha: &[F]) -> DensePolynomial<F>
    {
        self.packm.scale(Self::pack_scalars(evals, alpha))
    }
}
