/*****************************************************************************************************************

This source file implements generic constraint polynomials.

*****************************************************************************************************************/

use crate::constraints::ConstraintSystem;
use crate::polynomial::WitnessOverDomains;
use crate::scalars::ProofEvaluations;
use ark_ff::{FftField, SquareRootField};
use ark_poly::{univariate::DensePolynomial, Evaluations, Radix2EvaluationDomain as D};
use oracle::utils::PolyUtils;

impl<F: FftField + SquareRootField> ConstraintSystem<F> {
    // generic constraint quotient poly contribution computation
    pub fn gnrc_quot(
        &self,
        polys: &WitnessOverDomains<F>,
        p: &DensePolynomial<F>,
    ) -> (Evaluations<F, D<F>>, DensePolynomial<F>) {
        (
            &(&(&polys.d4.this.l * &polys.d4.this.r) * &self.qml)
                + &(&(&(&polys.d4.this.l * &self.qll) + &(&polys.d4.this.r * &self.qrl))
                    + &(&polys.d4.this.o * &self.qol)),
            &self.qc + p,
        )
    }

    pub fn gnrc_scalars(evals: &ProofEvaluations<F>) -> Vec<F> {
        vec![evals.l * &evals.r, evals.l, evals.r, evals.o, F::one()]
    }

    // generic constraint linearization poly contribution computation
    pub fn gnrc_lnrz(&self, evals: &ProofEvaluations<F>) -> DensePolynomial<F> {
        let scalars = Self::gnrc_scalars(evals);
        &(&(&(&self.qmm.scale(scalars[0]) + &self.qlm.scale(scalars[1]))
            + &self.qrm.scale(scalars[2]))
            + &self.qom.scale(scalars[3]))
            + &self.qc
    }
}
