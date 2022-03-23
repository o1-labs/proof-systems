use ark_ff::FftField;
use ark_poly::{EvaluationDomain, Evaluations, Radix2EvaluationDomain as Domain};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

#[serde_as]
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct EvaluationDomains<F: FftField> {
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub d1: Domain<F>, // size n
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub d2: Domain<F>, // size 2n
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub d4: Domain<F>, // size 4n
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub d8: Domain<F>, // size 8n
}

impl<F: FftField> EvaluationDomains<F> {
    /// Creates 4 evaluation domains `d1` (of size `n`), `d2` (of size `2n`), `d4` (of size `4n`),
    /// and `d8` (of size `8n`). If generator of `d8` is `g`, the generator
    /// of `d4` is `g^2`, the generator of `d2` is `g^4`, and the generator of `d1` is `g^8`.
    // TODO(mimoo): should we instead panic/return an error if any of these return None?
    pub fn create(n: usize) -> Option<Self> {
        let n = Domain::<F>::compute_size_of_domain(n)?;

        let d1 = Domain::<F>::new(n)?;

        // we also create domains of larger sizes
        // to efficiently operate on polynomials in evaluation form.
        // (in evaluation form, the domain needs to grow as the degree of a polynomial grows)
        let d2 = Domain::<F>::new(2 * n)?;
        let d4 = Domain::<F>::new(4 * n)?;
        let d8 = Domain::<F>::new(8 * n)?;

        // ensure the relationship between the three domains in case the library's behavior changes
        assert_eq!(d2.group_gen.square(), d1.group_gen);
        assert_eq!(d4.group_gen.square(), d2.group_gen);
        assert_eq!(d8.group_gen.square(), d4.group_gen);

        Some(EvaluationDomains { d1, d2, d4, d8 })
    }

    fn shift(&self, e: &Evaluations<F, Domain<F>>) -> usize {
        match e.domain().size() {
            x if x == self.d1.size() => 1,
            x if x == self.d2.size() => 2,
            x if x == self.d4.size() => 4,
            x if x == self.d8.size() => 8,
            _ => panic!("unrecognized domain used for the evaluations"),
        }
    }

    /// Changes the domain of an [Evaluations] to d1.
    pub fn to_d1(&self, e: &Evaluations<F, Domain<F>>) -> Evaluations<F, Domain<F>> {
        let shift = Self::shift(self, e);
        Evaluations::from_vec_and_domain(e.evals.iter().step_by(shift).cloned().collect(), self.d1)
    }

    /// Changes the domain of an [Evaluations] to d2.
    pub fn to_d2(&self, e: &Evaluations<F, Domain<F>>) -> Evaluations<F, Domain<F>> {
        let shift = Self::shift(self, e);
        if shift < 2 {
            e.interpolate_by_ref().evaluate_over_domain(self.d2)
        } else {
            Evaluations::from_vec_and_domain(
                e.evals.iter().step_by(shift).cloned().collect(),
                self.d2,
            )
        }
    }

    /// Changes the domain of an [Evaluations] to d4.
    pub fn to_d4(&self, e: &Evaluations<F, Domain<F>>) -> Evaluations<F, Domain<F>> {
        let shift = Self::shift(self, e);
        if shift < 4 {
            e.interpolate_by_ref().evaluate_over_domain(self.d4)
        } else {
            Evaluations::from_vec_and_domain(
                e.evals.iter().step_by(shift).cloned().collect(),
                self.d2,
            )
        }
    }

    /// Changes the domain of an [Evaluations] to d8.
    pub fn to_d8(&self, e: &Evaluations<F, Domain<F>>) -> Evaluations<F, Domain<F>> {
        let shift = Self::shift(self, e);
        if shift < 8 {
            e.interpolate_by_ref().evaluate_over_domain(self.d8)
        } else {
            Evaluations::from_vec_and_domain(
                e.evals.iter().step_by(shift).cloned().collect(),
                self.d2,
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::Field;
    use ark_poly::{univariate::DensePolynomial, Polynomial, UVPolynomial};
    use mina_curves::pasta::fp::Fp;
    use o1_utils::ExtendedEvaluations;
    use proptest::prelude::*;

    #[test]
    #[ignore] // TODO(mimoo): wait for fix upstream (https://github.com/arkworks-rs/algebra/pull/307)
    fn test_create_domain() {
        if let Some(d) = EvaluationDomains::<Fp>::create(usize::MAX) {
            assert!(d.d4.group_gen.pow(&[4]) == d.d1.group_gen);
            assert!(d.d8.group_gen.pow(&[2]) == d.d4.group_gen);
            println!("d8 = {:?}", d.d8.group_gen);
            println!("d8^2 = {:?}", d.d8.group_gen.pow(&[2]));
            println!("d4 = {:?}", d.d4.group_gen);
            println!("d4 = {:?}", d.d4.group_gen.pow(&[4]));
            println!("d1 = {:?}", d.d1.group_gen);
        }
    }

    proptest! {
        #[test]
        fn test_change_of_domain(first_domain in 0..4u8, second_domain in 0..4u8) {
            let domains = EvaluationDomains::<Fp>::create(1 << 8).unwrap();

            let some_domain = match first_domain {
                0 => domains.d1,
                1 => domains.d2,
                2 => domains.d4,
                3 => domains.d8,
                _ => panic!("unrecognized domain"),
            };

            // f(x) = 2x + 1 in some domain
            let poly = DensePolynomial::<Fp>::from_coefficients_slice(&[1u32.into(), 2u32.into()]);
            let evals = poly.evaluate_over_domain_by_ref(some_domain);

            // convert to a different domain
            let evals_other_domain = match second_domain {
                0 => domains.to_d1(&evals),
                1 => domains.to_d2(&evals),
                2 => domains.to_d4(&evals),
                3 => domains.to_d8(&evals),
                _ => panic!("unrecognized domain"),
            };

            // modify the polynomial
            let evals_other_domain = evals_other_domain.scale(2u32.into());

            // back to the first domain
            let evals_ = match first_domain {
                0 => domains.to_d1(&evals_other_domain),
                1 => domains.to_d2(&evals_other_domain),
                2 => domains.to_d4(&evals_other_domain),
                3 => domains.to_d8(&evals_other_domain),
                _ => panic!("unrecognized domain"),
            };

            // evaluate to the expected result
            assert_eq!(
                Fp::from(6u32),
                evals_.interpolate().evaluate(&1u32.into())
            );
        }
    }
}
