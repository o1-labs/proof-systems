use ark_ff::{batch_inversion_and_mul, FftField};
use ark_poly::{EvaluationDomain, Evaluations, Radix2EvaluationDomain as D};
use rayon::prelude::*;

/// The evaluations of all normalized lagrange basis polynomials at a given
/// point. Can be used to evaluate an `Evaluations` form polynomial at that point.
pub struct LagrangeBasisEvaluations<F> {
    evals: Vec<Vec<F>>,
}

impl<F: FftField> LagrangeBasisEvaluations<F> {
    /// Given the evaluations form of a polynomial, directly evaluate that polynomial at a point.
    pub fn evaluate<D: EvaluationDomain<F>>(&self, p: &Evaluations<F, D>) -> Vec<F> {
        assert_eq!(p.evals.len() % self.evals[0].len(), 0);
        let stride = p.evals.len() / self.evals[0].len();
        let p_evals = &p.evals;
        (&self.evals)
            .into_par_iter()
            .map(|evals| {
                evals
                    .into_par_iter()
                    .enumerate()
                    .map(|(i, e)| p_evals[stride * i] * e)
                    .sum()
            })
            .collect()
    }

    /// Given the evaluations form of a polynomial, directly evaluate that polynomial at a point,
    /// assuming that the given evaluations are either 0 or 1 at every point of the domain.
    pub fn evaluate_boolean<D: EvaluationDomain<F>>(&self, p: &Evaluations<F, D>) -> Vec<F> {
        assert_eq!(p.evals.len() % self.evals[0].len(), 0);
        let stride = p.evals.len() / self.evals[0].len();
        self.evals
            .iter()
            .map(|evals| {
                let mut result = F::zero();
                for (i, e) in evals.iter().enumerate() {
                    if !p.evals[stride * i].is_zero() {
                        result += e;
                    }
                }
                result
            })
            .collect()
    }

    /// Compute all evaluations of the normalized lagrange basis polynomials of the
    /// given domain at the given point. Runs in time O(domain size).
    fn new_with_segment_size_1(domain: D<F>, x: F) -> LagrangeBasisEvaluations<F> {
        let n = domain.size();
        // We want to compute for all i
        // s_i = 1 / t_i
        // where
        // t_i = prod_{j != i} (omega^i - omega^j)
        //
        // Suppose we have t_0 = prod_{j = 1}^{n-1} (1 - omega^j).
        // This is a product with n-1 terms. We want to shift each term over by omega
        // so we multiply by omega^{n-1}:
        //
        // omega^{n-1} * t_0
        // = prod_{j = 1}^{n-1} omega (1 - omega^j).
        // = prod_{j = 1}^{n-1} (omega - omega^{j+1)).
        // = (omega - omega^2) (omega - omega^3) ... (omega - omega^{n-1+1})
        // = (omega - omega^2) (omega - omega^3) ... (omega - omega^0)
        // = t_1
        //
        // And generally
        // omega^{n-1} * t_i
        // = prod_{j != i} omega (omega^i - omega^j)
        // = prod_{j != i} (omega^{i + 1} - omega^{j + 1})
        // = prod_{j + 1 != i + 1} (omega^{i + 1} - omega^{j + 1})
        // = prod_{j' != i + 1} (omega^{i + 1} - omega^{j'})
        // = t_{i + 1}
        //
        // Since omega^{n-1} = omega^{-1}, we write this as
        // omega{-1} t_i = t_{i + 1}
        // and then by induction,
        // omega^{-i} t_0 = t_i

        // Now, the ith lagrange evaluation at x is
        // (1 / prod_{j != i} (omega^i - omega^j)) (x^n - 1) / (x - omega^i)
        // = (x^n - 1) / [t_i (x - omega^i)]
        // = (x^n - 1) / [omega^{-i} * t_0 * (x - omega^i)]
        //
        // We compute this using the [batch_inversion_and_mul] function.

        let t_0: F = domain
            .elements()
            .skip(1)
            .map(|omega_i| F::one() - omega_i)
            .product();

        let mut denominators: Vec<F> = {
            let omegas: Vec<F> = domain.elements().collect();
            let omega_invs: Vec<F> = (0..n).map(|i| omegas[(n - i) % n]).collect();

            omegas
                .into_par_iter()
                .zip(omega_invs)
                .map(|(omega_i, omega_i_inv)| omega_i_inv * t_0 * (x - omega_i))
                .collect()
        };

        let numerator = x.pow([n as u64]) - F::one();

        batch_inversion_and_mul(&mut denominators[..], &numerator);

        // Denominators now contains the desired result.
        LagrangeBasisEvaluations {
            evals: vec![denominators],
        }
    }

    /// Compute all evaluations of the normalized lagrange basis polynomials of the
    /// given domain at the given point. Runs in time O(n log(n)) for n = domain size.
    fn new_with_chunked_segments(
        max_poly_size: usize,
        domain: D<F>,
        x: F,
    ) -> LagrangeBasisEvaluations<F> {
        let n = domain.size();
        let num_chunks = n / max_poly_size;
        let mut evals = Vec::with_capacity(num_chunks);
        for i in 0..num_chunks {
            let mut x_pow = F::one();
            let mut chunked_evals = vec![F::zero(); n];
            for j in 0..max_poly_size {
                chunked_evals[i * max_poly_size + j] = x_pow;
                x_pow *= x;
            }
            // This uses the same trick as `poly_commitment::srs::SRS::add_lagrange_basis`, but
            // applied to field elements instead of group elements.
            domain.ifft_in_place(&mut chunked_evals);
            evals.push(chunked_evals);
        }
        LagrangeBasisEvaluations { evals }
    }

    pub fn new(max_poly_size: usize, domain: D<F>, x: F) -> LagrangeBasisEvaluations<F> {
        if domain.size() <= max_poly_size {
            Self::new_with_segment_size_1(domain, x)
        } else {
            Self::new_with_chunked_segments(max_poly_size, domain, x)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use ark_ff::{One, UniformRand, Zero};
    use ark_poly::{Polynomial, Radix2EvaluationDomain};
    use mina_curves::pasta::Fp;
    use rand::{rngs::StdRng, SeedableRng};

    #[test]
    fn test_lagrange_evaluations() {
        let n = 1 << 4;
        let domain = Radix2EvaluationDomain::new(n).unwrap();
        let rng = &mut StdRng::from_seed([0u8; 32]);
        let x = Fp::rand(rng);
        let evaluator = LagrangeBasisEvaluations::new(domain.size(), domain, x);

        let expected = (0..n).map(|i| {
            let mut lagrange_i = vec![Fp::zero(); n];
            lagrange_i[i] = Fp::one();
            vec![Evaluations::from_vec_and_domain(lagrange_i, domain)
                .interpolate()
                .evaluate(&x)]
        });

        for (i, (expected, got)) in expected.zip(evaluator.evals).enumerate() {
            for (j, (expected, got)) in expected.iter().zip(got.iter()).enumerate() {
                if got != expected {
                    panic!("{}, {}, {}: {} != {}", line!(), i, j, got, expected);
                }
            }
        }
    }

    #[test]
    fn test_new_with_chunked_segments() {
        let n = 1 << 4;
        let domain = Radix2EvaluationDomain::new(n).unwrap();
        let rng = &mut StdRng::from_seed([0u8; 32]);
        let x = Fp::rand(rng);
        let evaluator = LagrangeBasisEvaluations::new(domain.size(), domain, x);
        let evaluator_chunked =
            LagrangeBasisEvaluations::new_with_chunked_segments(domain.size(), domain, x);
        for (i, (evals, evals_chunked)) in evaluator
            .evals
            .iter()
            .zip(evaluator_chunked.evals.iter())
            .enumerate()
        {
            for (j, (evals, evals_chunked)) in evals.iter().zip(evals_chunked.iter()).enumerate() {
                if evals != evals_chunked {
                    panic!("{}, {}, {}: {} != {}", line!(), i, j, evals, evals_chunked);
                }
            }
        }
    }

    #[test]
    fn test_evaluation() {
        let rng = &mut StdRng::from_seed([0u8; 32]);
        let n = 1 << 10;
        let domain = Radix2EvaluationDomain::new(n).unwrap();

        let evals = {
            let mut e = vec![];
            for _ in 0..n {
                e.push(Fp::rand(rng));
            }
            Evaluations::from_vec_and_domain(e, domain)
        };

        let x = Fp::rand(rng);

        let evaluator = LagrangeBasisEvaluations::new(domain.size(), domain, x);

        let y = evaluator.evaluate(&evals);
        let expected = vec![evals.interpolate().evaluate(&x)];
        assert_eq!(y, expected)
    }

    #[test]
    fn test_evaluation_boolean() {
        let rng = &mut StdRng::from_seed([0u8; 32]);
        let n = 1 << 1;
        let domain = Radix2EvaluationDomain::new(n).unwrap();

        let evals = {
            let mut e = vec![];
            for _ in 0..n {
                e.push(if bool::rand(rng) {
                    Fp::one()
                } else {
                    Fp::zero()
                });
            }
            e = vec![Fp::zero(), Fp::one()];
            Evaluations::from_vec_and_domain(e, domain)
        };

        let x = Fp::rand(rng);

        let evaluator = LagrangeBasisEvaluations::new(domain.size(), domain, x);

        let y = evaluator.evaluate_boolean(&evals);
        let expected = vec![evals.interpolate().evaluate(&x)];
        assert_eq!(y, expected)
    }
}
