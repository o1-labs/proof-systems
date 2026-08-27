use ark_ff::{batch_inversion_and_mul, FftField};
use ark_poly::{EvaluationDomain, Evaluations, Radix2EvaluationDomain as D};
use rayon::prelude::*;

/// Evaluations of all normalized lagrange basis polynomials at a given point.
/// Can be used to evaluate an `Evaluations` form polynomial at that point.
///
/// The Lagrange basis for polynomials of degree `<= d` over a domain
/// `{ω_0,...,ω_{d-1}}` is the set of `d` polynomials `{l_0,...,l_{d-1}}` of
/// degree `d-1` that equal `1` at `ω_i` and `0` in the rest of the domain
/// terms. They can be used to evaluate polynomials in evaluation form
/// efficiently in `O(d)` time.
///
/// When chunking is in place, the domain size `n` is larger than the maximum
/// polynomial degree allowed `m`. Thus, on input `n = c·m` evaluations for `c`
/// chunks, we cannot obtain a polynomial `f` with degree `c·m-1` with the equation:
///
/// `f(X) = x_0 · l_0(X) + ... + x_{c·m-1} · l_{c·m-1}(X)`
///
/// Instead, this struct will contain the `c·m` coefficients of the polynomial
/// that is equal to the powers of the point `x` in the positions corresponding
/// to the chunk, and `0` elsewhere in the domain. This is useful to evaluate the
/// chunks of polynomials of degree `c·m-1` given in evaluation form at the point.
pub struct LagrangeBasisEvaluations<F> {
    /// If no chunking:
    /// - evals is a vector of length 1 containing a vector of size `n`
    ///   corresponding to the evaluations of the Lagrange polynomials, which
    ///   are the polynomials that equal `1` at `ω_i` and `0` elsewhere in the
    ///   domain.
    ///
    /// If chunking (a vector of size `c · n`)
    /// - the first index refers to the chunks
    /// - the second index refers j-th coefficient of the i-th chunk of the
    ///   polynomial that equals the powers of the point and `0` elsewhere (and
    ///   the length of each such vector is `n`).
    evals: Vec<Vec<F>>,
}

impl<F: FftField> LagrangeBasisEvaluations<F> {
    /// Return the domain size of the individual evaluations.
    ///
    /// Note that there is an invariant that all individual evaluation chunks
    /// have the same size. It is enforced by each constructor.
    ///
    pub fn domain_size(&self) -> usize {
        self.evals[0].len()
    }

    /// Given the evaluations form of a polynomial, directly evaluate that
    /// polynomial at a point.
    ///
    /// The Lagrange basis evaluations can be used to evaluate a polynomial
    /// given in evaluation form efficiently in `O(n)` time, where `n` is the
    /// domain size, without the need of interpolating.
    ///
    /// Recall that a polynomial can be represented as the sum of the scaled
    /// Lagrange polynomials using its evaluations on the domain:
    /// `f(x) = x_0 · l_0(x) + ... + x_n · l_n(x)`
    ///
    /// But when chunking is in place, we want to evaluate a polynomial `f` of
    /// degree `c · m - 1` at point `z`, expressed as
    /// ```text
    /// f(z) = a_0·z^0 + ... + a_{c*m}·z^{c·m}
    ///      = z^0 · f_0(z) + z^m · f_1(z) + ... + z^{(c-1)m} · f_{c-1}(z)
    /// ```
    ///
    /// where `f_i(X)` is the i-th chunked polynomial of degree `m-1` of `f`:
    /// `f_i(x) = a_{i·m} · x^0 + ... + a_{(i+1)m-1} · x^{m-1}`
    ///
    /// Returns the evaluation of each chunk of the polynomial at the point
    /// (when there is no chunking, the result is a vector of length 1). They
    /// correspond to the `f_i(z)` in the equation above.
    pub fn evaluate<D: EvaluationDomain<F>>(&self, p: &Evaluations<F, D>) -> Vec<F> {
        // The domain size must be a multiple of the number of evaluations so
        // that the degree of the polynomial can be split into chunks of equal size.
        assert_eq!(p.evals.len() % self.domain_size(), 0);
        // The number of chunks c
        let stride = p.evals.len() / self.domain_size();
        let p_evals = &p.evals;

        // Performs the operation
        // ```text
        //                         n-1
        // j ∈ [0, c) : eval_{j} =  Σ   p_{i · c} · l_{j,i}
        //                         i=0
        // ```
        // Note that in the chunking case, the Lagrange basis contains the
        // coefficient form of the polynomial that evaluates to the powers of
        // `z` in the chunk positions and `0` elsewhere.
        //
        // Then, the evaluation of `f` on `z` can be computed as the sum of the
        // products of the evaluations of `f` in the domain and the Lagrange
        // evaluations.

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

    /// Given the evaluations form of a polynomial, directly evaluate that
    /// polynomial at a point, assuming that the given evaluations are either
    /// `0` or `1` at every point of the domain.
    ///
    /// This method can particularly be useful when the polynomials represent
    /// (boolean) selectors in a circuit.
    pub fn evaluate_boolean<D: EvaluationDomain<F>>(&self, p: &Evaluations<F, D>) -> Vec<F> {
        assert_eq!(p.evals.len() % self.domain_size(), 0);
        let stride = p.evals.len() / self.domain_size();
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

    /// Compute all evaluations of the normalized lagrange basis polynomials of
    /// the given domain at the given point. Runs in time O(domain size).
    fn new_with_segment_size_1(domain: D<F>, x: F) -> LagrangeBasisEvaluations<F> {
        let n = domain.size();
        // We want to compute for all i
        // s_i = 1 / t_i
        // where
        // t_i = ∏_{j ≠ i} (ω^i - ω^j)
        //
        // Suppose we have t_0 = ∏_{j = 1}^{n-1} (1 - ω^j).
        // This is a product with n-1 terms. We want to shift each term over by
        // ω so we multiply by ω^{n-1}:
        //
        // ω^{n-1} * t_0
        // = ∏_{j = 1}^{n-1} ω (1 - ω^j).
        // = ∏_{j = 1}^{n-1} (ω - ω^{j+1)).
        // = (ω - ω^2) (ω - ω^3) ... (ω - ω^{n-1+1})
        // = (ω - ω^2) (ω - ω^3) ... (ω - ω^0)
        // = t_1
        //
        // And generally
        // ω^{n-1} * t_i
        // = ∏_{j ≠ i} ω (ω^i - ω^j)
        // = ∏_{j ≠ i} (ω^{i + 1} - ω^{j + 1})
        // = ∏_{j + 1 ≠ i + 1} (ω^{i + 1} - ω^{j + 1})
        // = ∏_{j' ≠ i + 1} (ω^{i + 1} - ω^{j'})
        // = t_{i + 1}
        //
        // Since ω^{n-1} = ω^{-1}, we write this as
        // ω^{-1} t_i = t_{i + 1}
        // and then by induction,
        // ω^{-i} t_0 = t_i

        // Now, the ith Lagrange evaluation at x is
        // (1 / ∏_{j ≠ i} (ω^i - ω^j)) (x^n - 1) / (x - ω^i)
        // = (x^n - 1) / [t_i (x - ω^i)]
        // = (x^n - 1) / [ω^{-i} * t_0 * (x - ω^i)]
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

        // Denominators now contain the desired result.
        LagrangeBasisEvaluations {
            evals: vec![denominators],
        }
    }

    /// Compute all evaluations of the normalized Lagrange basis polynomials of
    /// the given domain at the given point `x`. Runs in time O(n log(n)) where
    /// n is the domain size.
    fn new_with_chunked_segments(
        max_poly_size: usize,
        domain: D<F>,
        x: F,
    ) -> LagrangeBasisEvaluations<F> {
        // For each chunk, this loop obtains the coefficient form of the
        // polynomial that equals the powers of `x` in the positions
        // corresponding to the chunk, and 0 elsewhere in the domain, using an
        // iFFT operation of length n, resulting in an algorithm that runs in
        // `O(c n log n)`.
        //
        // Example:
        // ```text
        //                                  i-th chunk
        //                          -----------------------
        //   chunked: [ 0, ..., 0,  1, x, x^2, ..., x^{m-1}, 0, ..., 0 ]
        //   indices:   0    i·m-1  i·m            (i+1)m-1  (i+1)m  cm-1=n-1
        // ```
        // A total of `n=c·m` coefficients are returned. These will be helpful to
        // evaluate the chunks of polynomials of degree `n-1` at the point `x`.
        //
        let n = domain.size();
        assert_eq!(n % max_poly_size, 0);
        let num_chunks = n / max_poly_size;
        let mut evals = Vec::with_capacity(num_chunks);
        for i in 0..num_chunks {
            let mut x_pow = F::one();
            let mut chunked_evals = vec![F::zero(); n];
            for j in 0..max_poly_size {
                chunked_evals[i * max_poly_size + j] = x_pow;
                x_pow *= x;
            }
            // This uses the same trick as `poly_commitment::srs::SRS::lagrange_basis`, but
            // applied to field elements instead of group elements.
            domain.ifft_in_place(&mut chunked_evals);
            // Check that the number of coefficients after iFFT is as expected
            assert_eq!(
                chunked_evals.len(),
                n,
                "The number of coefficients of the {}-th segment is {} but it should have been {n}",
                i,
                chunked_evals.len()
            );
            evals.push(chunked_evals);
        }
        // Sanity check
        assert_eq!(
            evals.len(),
            num_chunks,
            "The number of expected chunks is {num_chunks} but only {} has/have been computed",
            evals.len()
        );
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
    use rand::Rng;

    #[test]
    fn test_lagrange_evaluations() {
        let mut rng = o1_utils::tests::make_test_rng(None);
        let domain_log_size = rng.gen_range(1..10);
        let n = 1 << domain_log_size;
        let domain = Radix2EvaluationDomain::new(n).unwrap();
        let x = Fp::rand(&mut rng);
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
        let mut rng = o1_utils::tests::make_test_rng(None);
        let domain_log_size = rng.gen_range(1..10);
        let n = 1 << domain_log_size;
        let domain = Radix2EvaluationDomain::new(n).unwrap();
        let x = Fp::rand(&mut rng);
        let evaluator = LagrangeBasisEvaluations::new(domain.size(), domain, x);
        let evaluator_chunked =
            LagrangeBasisEvaluations::new_with_chunked_segments(domain.size(), domain, x);
        let chunk_length = evaluator_chunked.domain_size();
        for (i, (evals, evals_chunked)) in evaluator
            .evals
            .iter()
            .zip(evaluator_chunked.evals.iter())
            .enumerate()
        {
            // Check all chunks have the same length
            assert_eq!(evals_chunked.len(), chunk_length);
            for (j, (evals, evals_chunked)) in evals.iter().zip(evals_chunked.iter()).enumerate() {
                if evals != evals_chunked {
                    panic!("{}, {}, {}: {} != {}", line!(), i, j, evals, evals_chunked);
                }
            }
        }
    }

    #[test]
    fn test_evaluation() {
        let rng = &mut o1_utils::tests::make_test_rng(None);
        let domain_log_size = rng.gen_range(1..10);
        let n = 1 << domain_log_size;
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
        let rng = &mut o1_utils::tests::make_test_rng(None);
        let domain_log_size = rng.gen_range(1..10);
        let n = 1 << domain_log_size;
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
            Evaluations::from_vec_and_domain(e, domain)
        };

        let x = Fp::rand(rng);

        let evaluator = LagrangeBasisEvaluations::new(domain.size(), domain, x);

        let y = evaluator.evaluate_boolean(&evals);
        let expected = vec![evals.interpolate().evaluate(&x)];
        assert_eq!(y, expected)
    }
}
