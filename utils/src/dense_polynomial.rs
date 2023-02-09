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
    /// Implementors must ensure that the result contains at least 1 chunk.
    fn to_chunked_polynomial(&self, size: usize) -> ChunkedPolynomial<F>;
}

impl<F: Field> ExtendedDensePolynomial<F> for DensePolynomial<F> {
    fn scale(&self, elm: F) -> Self {
        let mut result = self.clone();
        result
            .coeffs
            .par_iter_mut()
            .for_each(|coeff| *coeff *= &elm);
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

    fn to_chunked_polynomial(&self, chunk_size: usize) -> ChunkedPolynomial<F> {
        // Ensure that there is always at least 1 polynomial in the resulting chunked polynomial.
        if self.coeffs.is_empty() {
            return ChunkedPolynomial {
                polys: vec![DensePolynomial::from_coefficients_vec(vec![])],
                size: chunk_size,
            };
        }

        let mut chunk_polys: Vec<DensePolynomial<F>> = vec![];
        for chunk in self.coeffs.chunks(chunk_size) {
            chunk_polys.push(DensePolynomial::from_coefficients_slice(chunk));
        }

        ChunkedPolynomial {
            polys: chunk_polys,
            size: chunk_size,
        }
    }
}

//
// Tests
//

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::One;
    use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial};
    use mina_curves::pasta::Fp;

    #[test]
    fn test_chunk() {
        let one = Fp::one();
        let two = one + one;
        let three = two + one;

        // 1 + x + x^2 + x^3 + x^4 + x^5 + x^6 + x^7
        let coeffs = [one, one, one, one, one, one, one, one];
        let f = DensePolynomial::from_coefficients_slice(&coeffs);
        let evals = f.to_chunked_polynomial(2).evaluate_chunks(two);
        for eval in evals.into_iter().take(4) {
            assert!(eval == three);
        }
    }
}
