use ark_ff::FftField;
use ark_poly::{
    univariate::DensePolynomial, Evaluations, Polynomial, Radix2EvaluationDomain as D, UVPolynomial,
};
use rayon::prelude::*;

// TODO(mimoo): these functions are also defined in dlog/commitment/src
pub trait PolyUtils<F: FftField> {
    /// This function "scales" (multiplies) polynomaial with a scalar
    /// It is implemented to have the desired functionality for DensePolynomial
    fn scale(&self, elm: F) -> Self;
    fn shiftr(&self, size: usize) -> Self;
    fn eval_polynomial(coeffs: &[F], x: F) -> F;
    /// This function evaluates polynomial in chunks
    fn eval(&self, elm: F, size: usize) -> Vec<F>;
}

pub trait EvalUtils<F: FftField> {
    /// This function "scales" (multiplies) a polynomial with a scalar
    /// It is implemented to have the desired functionality for DensePolynomial
    fn scale(&self, elm: F) -> Self;
    fn square(&self) -> Self;
    fn pow(&self, pow: usize) -> Self;
    /// utility function for shifting poly along domain coordinate
    fn shift(&self, len: usize) -> Self;
}

impl<F: FftField> EvalUtils<F> for Evaluations<F, D<F>> {
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

impl<F: FftField> PolyUtils<F> for DensePolynomial<F> {
    fn eval_polynomial(coeffs: &[F], x: F) -> F {
        let mut res = F::zero();
        for c in coeffs.iter().rev() {
            res *= &x;
            res += c;
        }
        res
    }

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

    fn eval(&self, elm: F, size: usize) -> Vec<F> {
        let mut res = vec![];
        for chunk in self.coeffs.chunks(size) {
            let eval = Self::from_coefficients_slice(chunk).evaluate(elm);
            res.push(eval);
        }
        res
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use algebra::{pasta::fp::Fp, One, Zero};

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
