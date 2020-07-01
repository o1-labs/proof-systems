/*****************************************************************************************************************

This source file implements generic constraint polynomials.

*****************************************************************************************************************/

use algebra::{FftField, SquareRootField};
use ff_fft::{Evaluations, DensePolynomial};
use crate::polynomials::WitnessOverDomains;
use oracle::utils::{EvalUtils, PolyUtils};
use crate::constraints::ConstraintSystem;
use crate::scalars::ProofEvaluations;

impl<F: FftField + SquareRootField> ConstraintSystem<F> 
{
    // generic constraint quotient poly contribution computation
    pub fn gnrc_quot(&self, polys: &WitnessOverDomains<F>, p: &DensePolynomial<F>) -> DensePolynomial<F>
    {
        &(&(&Evaluations::multiply(&[&polys.d2.this.l, &polys.d2.this.r, &self.qml], self.domain.d2) +
        &(
            &(&Evaluations::multiply(&[&polys.d2.this.l, &self.qll], self.domain.d2) +
            &Evaluations::multiply(&[&polys.d2.this.r, &self.qrl], self.domain.d2)) +
            &Evaluations::multiply(&[&polys.d2.this.o, &self.qol], self.domain.d2)
        )).interpolate() +
        &self.qc) + p
    }

    // generic constraint linearization poly contribution computation
    pub fn gnrc_lnrz(&self, evals: &ProofEvaluations<F>) -> DensePolynomial<F>
    {
        &(&(&(&self.qmm.scale(evals.l*evals.r) + &self.qlm.scale(evals.l)) +
            &self.qrm.scale(evals.r)) + &self.qom.scale(evals.o)) + &self.qc

    }
}
