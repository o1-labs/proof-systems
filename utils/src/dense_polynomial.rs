//! This adds a few utility functions for the [DensePolynomial] arkworks type.

use ark_ff::Field;
use ark_poly::{univariate::DensePolynomial, Polynomial, UVPolynomial};
use serde_with::{DeserializeAs, SerializeAs};

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

    /// This function evaluates polynomial in chunks.
    fn eval(&self, elm: F, size: usize) -> Vec<F>;

    /// Multiplies the chunks of a polynomial with powers of zeta^n
    fn chunk_polynomial(&self, zeta_n: F, n: usize) -> Self;
}

impl<F: Field> ExtendedDensePolynomial<F> for DensePolynomial<F> {
    fn scale(&self, elm: F) -> Self {
        let mut result = self.clone();
        for coeff in &mut result.coeffs {
            *coeff *= &elm
        }
        result
    }

    fn shiftr(&self, size: usize) -> Self {
        let mut result = vec![F::zero(); size];
        result.extend(self.coeffs.clone());
        DensePolynomial::<F>::from_coefficients_vec(result)
    }

    fn eval_polynomial(coeffs: &[F], x: F) -> F {
        // this uses https://en.wikipedia.org/wiki/Horner%27s_method
        let mut res = F::zero();
        for c in coeffs.iter().rev() {
            res *= &x;
            res += c;
        }
        res
    }

    fn eval(&self, elm: F, size: usize) -> Vec<F> {
        let mut res = vec![];
        for chunk in self.coeffs.chunks(size) {
            let eval = Self::from_coefficients_slice(chunk).evaluate(&elm);
            res.push(eval);
        }
        res
    }

    fn chunk_polynomial(&self, zeta_n: F, n: usize) -> Self {
        let mut scale = F::one();
        let mut coeffs = vec![F::zero(); n];

        for chunk in self.coeffs.chunks(n) {
            for (j, c) in chunk.iter().enumerate() {
                coeffs[j] += scale * c;
            }
            scale *= zeta_n;
        }

        DensePolynomial { coeffs }
    }
}

//
// Tests
//

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::{One, Zero};
    use ark_poly::{univariate::DensePolynomial, UVPolynomial};
    use mina_curves::pasta::fp::Fp;

    #[test]
    fn test_eval() {
        let zero = Fp::zero();
        let one = Fp::one();
        // 1 + x^2 + x^4 + x^8
        let coeffs = [one, zero, one, zero, one, zero, one, zero];
        let f = DensePolynomial::from_coefficients_slice(&coeffs);
        let evals = f.eval(one, 2);
        for i in 0..4 {
            assert!(evals[i] == one);
        }
    }
}
