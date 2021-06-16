/*****************************************************************************************************************

This source file implements generic constraint polynomials.

*****************************************************************************************************************/

use crate::constraints::ConstraintSystem;
use crate::polynomial::WitnessOverDomains;
use crate::scalars::ProofEvaluations;
use ark_ff::{FftField, SquareRootField, Zero};
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
            &(&(&polys.d4.this.w[0] * &polys.d4.this.w[1]) * &self.qml)
                + &polys
                    .d4
                    .this
                    .w
                    .iter()
                    .zip(self.qwl.iter())
                    .map(|(w, q)| w * q)
                    .fold(self.zero4.clone(), |x, y| &x + &y),
            &self.qc + &p,
        )
    }

    pub fn gnrc_scalars(evals: &ProofEvaluations<F>) -> Vec<F> {
        vec![
            evals.w[0] * &evals.w[1],
            evals.w[0],
            evals.w[1],
            evals.w[2],
            evals.w[3],
            evals.w[4],
            F::one(),
        ]
    }

    // generic constraint linearization poly contribution computation
    pub fn gnrc_lnrz(&self, evals: &ProofEvaluations<F>) -> DensePolynomial<F> {
        let scalars = Self::gnrc_scalars(evals);
        &(&self.qmm.scale(scalars[0]) + &self.qc)
            + &self
                .qwm
                .iter()
                .zip(scalars[1..].iter())
                .map(|(q, s)| q.scale(*s))
                .fold(DensePolynomial::<F>::zero(), |x, y| &x + &y)
    }
}
