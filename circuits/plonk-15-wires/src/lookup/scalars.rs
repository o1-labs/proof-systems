/*****************************************************************************************************************

This source file implements Plonk prover polynomial evaluations primitive.

*****************************************************************************************************************/

use crate::nolookup::scalars::{ProofEvaluations as PE, RandomOracles as RO};
use ark_ff::{FftField, Field};
use ark_poly::univariate::DensePolynomial;
use o1_utils::ExtendedDensePolynomial;

#[derive(Clone)]
pub struct ProofEvaluations<Fs> {
    // Plonk evals
    pub pe: PE<Fs>,

    // Plookup evals
    pub l: Fs,  // lookup aggregaion
    pub lw: Fs, // lookup witness
    pub h1: Fs, // lookup multiset
    pub h2: Fs, // lookup multiset
    pub tb: Fs, // lookup table
}

impl<F: FftField> ProofEvaluations<Vec<F>> {
    pub fn combine(&self, pt: F) -> ProofEvaluations<F> {
        ProofEvaluations::<F> {
            pe: PE::<Vec<F>>::combine(&self.pe, pt),
            l: DensePolynomial::eval_polynomial(&self.l, pt),
            lw: DensePolynomial::eval_polynomial(&self.lw, pt),
            h1: DensePolynomial::eval_polynomial(&self.h1, pt),
            h2: DensePolynomial::eval_polynomial(&self.h2, pt),
            tb: DensePolynomial::eval_polynomial(&self.tb, pt),
        }
    }
}

#[derive(Clone, Debug)]
pub struct RandomOracles<F: Field> {
    // Plonk oracles
    pub po: RO<F>,

    // Plookup oracles
    pub beta: F,
    pub gamma: F,
}

impl<F: Field> RandomOracles<F> {
    pub fn zero() -> Self {
        Self {
            po: RO::<F>::default(),
            beta: F::zero(),
            gamma: F::zero(),
        }
    }
}
