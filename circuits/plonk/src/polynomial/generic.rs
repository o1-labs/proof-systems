/*****************************************************************************************************************

This source file implements generic constraint polynomials.

*****************************************************************************************************************/

use algebra::{FftField, SquareRootField};
use ff_fft::{Evaluations, DensePolynomial, Radix2EvaluationDomain as D};
use crate::polynomials::WitnessOverDomains;
use crate::constraints::ConstraintSystem;
use crate::scalars::ProofEvaluations;
use oracle::utils::PolyUtils;

impl<F: FftField + SquareRootField> ConstraintSystem<F> 
{
    // generic constraint quotient poly contribution computation
    pub fn gnrc_quot(&self, polys: &WitnessOverDomains<F>, p: &DensePolynomial<F>) -> (Evaluations<F, D<F>>, DensePolynomial<F>)
    {
        (
            &(&(&polys.d2.this.l * &polys.d2.this.r) * &self.qml) +
            &(
                &(&(&polys.d2.this.l * &self.qll) +
                &(&polys.d2.this.r * &self.qrl)) +
                &(&polys.d2.this.o * &self.qol)
            ),
            &self.qc + &p
        )
    }

    // generic constraint linearization poly contribution computation
    pub fn gnrc_lnrz(&self, evals: &ProofEvaluations<F>) -> DensePolynomial<F>
    {
        &(&(&(&self.qmm.scale(evals.l*evals.r) + &self.qlm.scale(evals.l)) +
            &self.qrm.scale(evals.r)) + &self.qom.scale(evals.o)) + &self.qc

    }
}
