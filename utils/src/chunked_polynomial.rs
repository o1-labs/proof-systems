//! This module contains a type [`ChunkedPolynomial`],
//! and a number of helper methods to deal with chunked polynomials.
//! Polynomials that cut in several polynomials of the same length.

use ark_ff::Field;
use ark_poly::polynomial::{univariate::DensePolynomial, Polynomial};

/// This struct contains multiple chunk polynomials with degree `size-1`.
#[derive(Clone)]
pub struct ChunkedPolynomial<F: Field> {
    /// The chunk polynomials.
    pub polys: Vec<DensePolynomial<F>>,

    /// Each chunk polynomial has degree `size-1`.
    pub size: usize,
}

impl<F: Field> ChunkedPolynomial<F> {
    /// This function evaluates polynomial in chunks.
    pub fn evaluate_chunks(&self, elm: F) -> Vec<F> {
        let mut res: Vec<F> = vec![];
        for poly in &self.polys {
            let eval = poly.evaluate(&elm);
            res.push(eval);
        }
        res
    }

    /// Multiplies the chunks of a polynomial with powers of zeta^n to make it of degree n-1.
    /// For example, if a polynomial can be written `f = f0 + x^n f1 + x^2n f2`
    /// (where f0, f1, f2 are of degree n-1), then this function returns the new semi-evaluated
    /// `f'(x) = f0(x) + zeta^n f1(x) + zeta^2n f2(x)`.
    pub fn linearize(&self, zeta_n: F) -> DensePolynomial<F> {
        let mut scale = F::one();
        let mut coeffs = vec![F::zero(); self.size];

        for poly in &self.polys {
            for (coeff, poly_coeff) in coeffs.iter_mut().zip(&poly.coeffs) {
                *coeff += scale * poly_coeff;
            }

            scale *= zeta_n;
        }

        while coeffs.last().is_some_and(F::is_zero) {
            coeffs.pop();
        }

        DensePolynomial { coeffs }
    }
}
