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

    /// Convert the evaluations in a specific domain to a smaller domain.
    ///
    /// Optionally allows:
    ///
    /// - a constant to be added (to the polynomial in evaluation form)
    /// - a shift of the values (equivalent to multiplying with a power of the domain generator)
    ///
    /// # Warning
    ///
    /// To ensure that the target domain is large enough for the polynomial,
    /// the caller must provide the degree of the polynomial as well.
    ///
    /// To ensure that the shift provided is given considering the domain used for the circuit,
    /// which could be unrelated to the current domain or the target domain,
    /// we have the caller pass the circuit domain as well.
    ///
    /// Why? Imagine that the circuit domain is d1, and we are in d4, and we want to move to d2.
    /// All of that with a shift of 1. Then we have to shift by 4:
    ///
    /// d4 := [1, w, w^2, w^3, w^4, w^5, w^6, w^7, w^8, ...] <-- current domain
    /// d2 := [1, _, w^2,      w^4,      w^6,    , w^8, ...] <--  target domain
    /// d1 := [1,    ___,      w^4,                w^8, ...] <-- circuit domain
    ///  
    ///  ---> [_,              w^4,                w^8, ...] <-- shift of 1
    ///
    /// # Panics
    ///
    /// Panics if the `target_domain` is larger than the current domain size,
    /// or if the degree of the polynomial is too large for the target domain.
    ///
    fn to_domain(
        &self,
        degree: usize,
        target_domain: Radix2EvaluationDomain<F>,
        circuit_domain: Radix2EvaluationDomain<F>,
        shift: Option<usize>,
        constant: Option<F>,
    ) -> Self;
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

    fn to_domain(
        &self,
        degree: usize,
        target_domain: Radix2EvaluationDomain<F>,
        circuit_domain: Radix2EvaluationDomain<F>,
        shift: Option<usize>,
        constant: Option<F>,
    ) -> Evaluations<F, Radix2EvaluationDomain<F>> {
        let domain_size = self.domain().size(); // e.g. d8
        let target_size = target_domain.size(); // e.g. d4
        let scale = domain_size / target_size;
        let scale_from_circuit = domain_size / circuit_domain.size();

        // sanity checks
        if cfg!(debug_assertions) {
            assert_ne!(domain_size, 0);
            assert_ne!(target_size, 0);

            assert!(
                degree < target_size,
                "target domain must be large enough to hold the polynomial"
            );

            assert_eq!(
                domain_size % target_size,
                0,
                "target domain must be a multiple of domain size, and smaller"
            );

            assert_eq!(
                target_size % circuit_domain.size(),
                0,
                "target domain must be a multiple of the circuit domain"
            );
            assert_eq!(
                self.domain().group_gen.pow(&[scale_from_circuit as u64]),
                circuit_domain.group_gen,
                "the circuit domain must be a subgroup of the current domain"
            );

            assert_eq!(
                self.domain().group_gen.pow(&[scale as u64]),
                target_domain.group_gen,
                "the target domain must be a subgroup of the current domain"
            );
        }

        // get new evals
        let shift = shift.unwrap_or(0);
        let cst = constant.unwrap_or_else(F::zero);
        let f = |i| {
            // for example, to go from d8 to d4, you collect every 2nd element
            let idx = (scale * i + scale_from_circuit * shift) % self.evals.len();
            cst + self.evals[idx]
        };
        let new_evals = (0..target_size).into_par_iter().map(f).collect();

        Evaluations::from_vec_and_domain(new_evals, target_domain)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use ark_ff::Field;
    use ark_poly::{univariate::DensePolynomial, Polynomial, UVPolynomial};
    use mina_curves::pasta::Fp as F;

    #[test]
    fn test_conv_domain() {
        let d4 = Radix2EvaluationDomain::<F>::new(4).unwrap();
        let d8 = Radix2EvaluationDomain::<F>::new(8).unwrap();

        let coeffs = vec![1u8, 2, 3, 4].into_iter().map(F::from).collect();
        let poly = DensePolynomial::from_coefficients_vec(coeffs);
        let evals_d8 = poly.evaluate_over_domain_by_ref(d8);

        // check normal conversaion
        let evals_d4 = evals_d8.to_domain(poly.degree(), d4, d4, None, None);
        assert_eq!(evals_d4.interpolate(), poly);

        // check with constants
        let evals_d4 = evals_d8.to_domain(poly.degree(), d4, d4, None, Some(F::from(0u8)));
        assert_eq!(evals_d4.interpolate(), poly);

        let evals_d4 = evals_d8.to_domain(poly.degree(), d4, d4, None, Some(F::from(10u8)));
        assert_eq!(
            evals_d4.interpolate(),
            &poly + &DensePolynomial::from_coefficients_slice(&[10.into()])
        );

        // check with shift (poly(x) -> poly(x * w^2))
        let evals_d4 = evals_d8.to_domain(poly.degree(), d4, d4, Some(2), Some(F::from(0u8)));
        let gen_coeffs = (0..poly.coeffs.len())
            .into_iter()
            .map(|i| d4.group_gen.pow(&[i as u64 * 2]));
        let shifted_poly = DensePolynomial::from_coefficients_vec(
            poly.coeffs
                .iter()
                .zip(gen_coeffs)
                .map(|(a, b)| b * a)
                .collect(),
        );
        assert_eq!(evals_d4.interpolate(), shifted_poly);
    }

    #[test]
    #[should_panic]
    fn test_conv_domain_too_high_degree() {
        let d4 = Radix2EvaluationDomain::<F>::new(4).unwrap();
        let d8 = Radix2EvaluationDomain::<F>::new(8).unwrap();

        let coeffs = vec![1u8, 2, 3, 4, 5].into_iter().map(F::from).collect();
        let poly = DensePolynomial::from_coefficients_vec(coeffs);
        let evals_d8 = poly.evaluate_over_domain_by_ref(d8);

        let _evals_d4 = evals_d8.to_domain(poly.degree(), d4, d4, None, None);
    }
}
