//! This module contains a type [ChunkedPolynomial],
//! and a number of helper methods to deal with chunked polynomials.
//! Polynomials that cut in several polynomials of the same length.

use ark_ff::Field;
use ark_poly::polynomial::{univariate::DensePolynomial, Polynomial};

/// This struct contains multiple chunk polynomials with degree `size-1`.
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
        for poly in self.polys.iter() {
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

        for poly in self.polys.iter() {
            for (coeff, poly_coeff) in coeffs.iter_mut().zip(&poly.coeffs) {
                *coeff += scale * poly_coeff;
            }

            scale *= zeta_n;
        }

        while coeffs.last().map_or(false, |c| c.is_zero()) {
            coeffs.pop();
        }

        DensePolynomial { coeffs }
    }
}

#[cfg(test)]
mod tests {
    use crate::ExtendedDensePolynomial;

    use super::*;
    use ark_ff::One;
    use ark_poly::{univariate::DensePolynomial, UVPolynomial};
    use mina_curves::pasta::fp::Fp;

    #[test]

    fn test_chunk_poly() {
        let one = Fp::one();
        let zeta = one + one;
        let zeta_n = zeta.square();
        let res = (one + zeta)
            * (one + zeta_n + zeta_n * zeta.square() + zeta_n * zeta.square() * zeta.square());

        // 1 + x + x^2 + x^3 + x^4 + x^5 + x^6 + x^7 = (1+x) + x^2 (1+x) + x^4 (1+x) + x^6 (1+x)
        let coeffs = [one, one, one, one, one, one, one, one];
        let f = DensePolynomial::from_coefficients_slice(&coeffs);

        let eval = f.to_chunked_polynomial(2).linearize(zeta_n).evaluate(&zeta);

        assert!(eval == res);
    }
}
