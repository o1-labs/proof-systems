//! This adds a few utility functions for the [Evaluations] arkworks type.

use ark_ff::FftField;
use ark_poly::{EvaluationDomain, Evaluations, Radix2EvaluationDomain};
use rayon::prelude::*;

/// An extension for the [Evaluations] type.
pub trait ExtendedEvaluations<F: FftField> {
    /// This function "scales" (multiplies) a polynomial with a scalar
    /// It is implemented to have the desired functionality for DensePolynomial
    fn scale(&self, elm: F) -> Self;

    /// Square each evaluation
    fn square(&self) -> Self;

    /// Raise each evaluation to some power `pow`
    fn pow(&self, pow: usize) -> Self;

    /// Utility function for shifting poly along domain coordinate
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

/// Cast the evaluations in specfic domain size to the smaller domain size.
///
/// ## Panics
///
/// Panics if `evals_domain_size` is smaller than `target_domain_size`.
pub fn to_domain<F: FftField>(
    evals: &Evaluations<F, Radix2EvaluationDomain<F>>,
    evals_domain_size: usize,
    target_domain_size: usize,
    target_domain: Radix2EvaluationDomain<F>,
    shift: Option<usize>,
    constant: Option<F>,
) -> Evaluations<F, Radix2EvaluationDomain<F>> {
    let scale = evals_domain_size / target_domain_size;
    assert_ne!(
        scale, 0,
        "we can't move to a bigger domain without interpolating and reevaluating the polynomial"
    );
    let shift = shift.unwrap_or(0);
    let f = |i| {
        if let Some(cst) = constant {
            cst + evals.evals[(scale * i + evals_domain_size * shift) % evals.evals.len()]
        } else {
            evals.evals[(scale * i + evals_domain_size * shift) % evals.evals.len()]
        }
    };
    let new_evals = (0..target_domain.size()).into_par_iter().map(f).collect();
    Evaluations::from_vec_and_domain(new_evals, target_domain)
}
