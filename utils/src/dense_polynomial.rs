//! This adds a few utility functions for the [DensePolynomial] arkworks type.

use ark_ff::Field;
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, Polynomial};
use rayon::prelude::*;

use crate::chunked_polynomial::ChunkedPolynomial;

//
// ExtendedDensePolynomial trait
//

/// An extension for the [DensePolynomial] type.
pub trait ExtendedDensePolynomial<F: Field> {
    /// This function "scales" (multiplies all the coefficients of) a polynomial with a scalar.
    fn scale(&self, elm: F) -> Self;

    /// Shifts all the coefficients to the right.
    fn shiftr(&self, size: usize) -> Self;

    /// `eval_polynomial(coeffs, x)` evaluates a polynomial given its coefficients `coeffs` and a point `x`.
    fn eval_polynomial(coeffs: &[F], x: F) -> F;

    /// Convert a polynomial into chunks.
    /// Implementers must ensure that the result contains exactly num_chunks.
    fn to_chunked_polynomial(&self, num_chunks: usize, size: usize) -> ChunkedPolynomial<F>;
}

impl<F: Field> ExtendedDensePolynomial<F> for DensePolynomial<F> {
    fn scale(&self, elm: F) -> Self {
        let mut result = self.clone();
        result
            .coeffs
            .par_iter_mut()
            .for_each(|coeff: &mut F| *coeff *= &elm);
        result
    }

    fn shiftr(&self, size: usize) -> Self {
        let mut result = vec![F::zero(); size];
        result.extend(self.coeffs.clone());
        DensePolynomial::<F>::from_coefficients_vec(result)
    }

    fn eval_polynomial(coeffs: &[F], x: F) -> F {
        DensePolynomial::from_coefficients_slice(coeffs).evaluate(&x)
    }

    fn to_chunked_polynomial(&self, num_chunks: usize, chunk_size: usize) -> ChunkedPolynomial<F> {
        let mut chunk_polys: Vec<DensePolynomial<F>> = Vec::with_capacity(num_chunks);
        for chunk in self.coeffs.chunks(chunk_size) {
            chunk_polys.push(DensePolynomial::from_coefficients_slice(chunk));
        }

        // Pad unused chunks with zeros.
        for _ in chunk_polys.len()..num_chunks {
            chunk_polys.push(DensePolynomial::from_coefficients_vec(vec![]));
        }

        // Ensuring that the number of chunks is the one requested, following
        // trait documentation
        assert_eq!(chunk_polys.len(), num_chunks);

        ChunkedPolynomial {
            polys: chunk_polys,
            size: chunk_size,
        }
    }
}
