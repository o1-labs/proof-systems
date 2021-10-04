//! This adds a few utility functions for the [Evaluations] arkworks type.

use ark_ff::FftField;
use ark_poly::{Evaluations, Radix2EvaluationDomain};
use rayon::prelude::*;
use serde_with::{DeserializeAs, SerializeAs};

/// An extension for the [Evaluations] type.
pub trait ExtendedEvaluations<F: FftField> {
    /// This function "scales" (multiplies) a polynomial with a scalar
    /// It is implemented to have the desired functionality for DensePolynomial
    fn scale(&self, elm: F) -> Self;
    /// square each evaluation
    fn square(&self) -> Self;
    /// raise each evaluation to some power `pow`
    fn pow(&self, pow: usize) -> Self;
    /// utility function for shifting poly along domain coordinate
    fn shift(&self, len: usize) -> Self;
}

impl<F: FftField> ExtendedEvaluations<F> for Evaluations<F, Radix2EvaluationDomain<F>> {
    fn scale(&self, elm: F) -> Self {
        let mut result = self.clone();
        result.evals.par_iter_mut().for_each(|coeff| *coeff *= &elm);
        result
    }

    fn square(&self) -> Self {
        let mut result = self.clone();
        result.evals.par_iter_mut().for_each(|e| {
            let _ = e.square_in_place();
        });
        result
    }

    fn pow(&self, pow: usize) -> Self {
        let mut result = self.clone();
        result
            .evals
            .par_iter_mut()
            .for_each(|e| *e = e.pow([pow as u64]));
        result
    }

    fn shift(&self, len: usize) -> Self {
        let len = len % self.evals.len();
        let mut result = self.clone();
        result.evals.clear();
        result.evals = self.evals[len..].to_vec();
        let mut tail = self.evals[0..len].to_vec();
        result.evals.append(&mut tail);
        result
    }
}
