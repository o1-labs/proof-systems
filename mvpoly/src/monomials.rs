use crate::{
    prime,
    utils::{compute_indices_nested_loop, naive_prime_factors, PrimeNumberGenerator},
    MVPoly,
};
use ark_ff::{One, PrimeField, Zero};
use kimchi::circuits::{expr::Variable, gate::CurrOrNext};
use num_integer::binomial;
use rand::{Rng, RngCore};
use std::{
    collections::HashMap,
    fmt::Debug,
    ops::{Add, Mul, Neg, Sub},
};

/// Represents a multivariate polynomial in `N` variables with coefficients in
/// `F`. The polynomial is represented as a sparse polynomial, where each
/// monomial is represented by a vector of `N` exponents.
///
/// For instance, the multivariate polynomial `3x^2 y + 2 x z` will be
/// represented by the HashMap:
/// ```text
/// [2, 1, 0] -> 3
///  |  |  |
///  x  y  z
///  |  |  |
/// [1, 0, 1] -> 2
/// ```
// We could use u8 instead of usize for the exponents
// FIXME: the maximum degree D is encoded in the type to match the type
// prime::Dense
#[derive(Clone)]
pub struct Sparse<F: PrimeField, const N: usize, const D: usize> {
    pub monomials: HashMap<[usize; N], F>,
}

impl<const N: usize, const D: usize, F: PrimeField> Add for Sparse<F, N, D> {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        &self + &other
    }
}

impl<const N: usize, const D: usize, F: PrimeField> Add<&Sparse<F, N, D>> for Sparse<F, N, D> {
    type Output = Sparse<F, N, D>;

    fn add(self, other: &Sparse<F, N, D>) -> Self::Output {
        &self + other
    }
}

impl<const N: usize, const D: usize, F: PrimeField> Add<Sparse<F, N, D>> for &Sparse<F, N, D> {
    type Output = Sparse<F, N, D>;

    fn add(self, other: Sparse<F, N, D>) -> Self::Output {
        self + &other
    }
}
impl<const N: usize, const D: usize, F: PrimeField> Add<&Sparse<F, N, D>> for &Sparse<F, N, D> {
    type Output = Sparse<F, N, D>;

    fn add(self, other: &Sparse<F, N, D>) -> Self::Output {
        let mut monomials = self.monomials.clone();
        for (exponents, coeff) in &other.monomials {
            monomials
                .entry(*exponents)
                .and_modify(|c| *c += *coeff)
                .or_insert(*coeff);
        }
        // Remove monomials with zero coefficients
        let monomials: HashMap<[usize; N], F> = monomials
            .into_iter()
            .filter(|(_, coeff)| !coeff.is_zero())
            .collect();
        // Handle the case where the result is zero because we want a unique
        // representation
        if monomials.is_empty() {
            Sparse::<F, N, D>::zero()
        } else {
            Sparse::<F, N, D> { monomials }
        }
    }
}

impl<const N: usize, const D: usize, F: PrimeField> Debug for Sparse<F, N, D> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut monomials: Vec<String> = self
            .monomials
            .iter()
            .map(|(exponents, coeff)| {
                let mut monomial = format!("{}", coeff);
                for (i, exp) in exponents.iter().enumerate() {
                    if *exp == 0 {
                        continue;
                    } else if *exp == 1 {
                        monomial.push_str(&format!("x_{}", i));
                    } else {
                        monomial.push_str(&format!("x_{}^{}", i, exp));
                    }
                }
                monomial
            })
            .collect();
        monomials.sort();
        write!(f, "{}", monomials.join(" + "))
    }
}

impl<const N: usize, const D: usize, F: PrimeField> Mul for Sparse<F, N, D> {
    type Output = Self;

    fn mul(self, other: Self) -> Self {
        let mut monomials = HashMap::new();
        let degree_lhs = unsafe { self.degree() };
        let degree_rhs = unsafe { other.degree() };
        assert!(degree_lhs + degree_rhs <= D, "The degree of the output is expected to be maximum {D}, but the resulting output would be larger than {D} ({res})", res=degree_lhs + degree_rhs);
        self.monomials.iter().for_each(|(exponents1, coeff1)| {
            other
                .monomials
                .clone()
                .iter()
                .for_each(|(exponents2, coeff2)| {
                    let mut exponents = [0; N];
                    for i in 0..N {
                        exponents[i] = exponents1[i] + exponents2[i];
                    }
                    monomials
                        .entry(exponents)
                        .and_modify(|c| *c += *coeff1 * *coeff2)
                        .or_insert(*coeff1 * *coeff2);
                })
        });
        // Remove monomials with zero coefficients
        let monomials: HashMap<[usize; N], F> = monomials
            .into_iter()
            .filter(|(_, coeff)| !coeff.is_zero())
            .collect();
        if monomials.is_empty() {
            Self::zero()
        } else {
            Self { monomials }
        }
    }
}

impl<const N: usize, const D: usize, F: PrimeField> Neg for Sparse<F, N, D> {
    type Output = Sparse<F, N, D>;

    fn neg(self) -> Self::Output {
        -&self
    }
}

impl<const N: usize, const D: usize, F: PrimeField> Neg for &Sparse<F, N, D> {
    type Output = Sparse<F, N, D>;

    fn neg(self) -> Self::Output {
        let monomials: HashMap<[usize; N], F> = self
            .monomials
            .iter()
            .map(|(exponents, coeff)| (*exponents, -*coeff))
            .collect();
        Sparse::<F, N, D> { monomials }
    }
}

impl<const N: usize, const D: usize, F: PrimeField> Sub for Sparse<F, N, D> {
    type Output = Sparse<F, N, D>;

    fn sub(self, other: Sparse<F, N, D>) -> Self::Output {
        self + (-other)
    }
}

impl<const N: usize, const D: usize, F: PrimeField> Sub<&Sparse<F, N, D>> for Sparse<F, N, D> {
    type Output = Sparse<F, N, D>;

    fn sub(self, other: &Sparse<F, N, D>) -> Self::Output {
        self + (-other)
    }
}

impl<const N: usize, const D: usize, F: PrimeField> Sub<Sparse<F, N, D>> for &Sparse<F, N, D> {
    type Output = Sparse<F, N, D>;

    fn sub(self, other: Sparse<F, N, D>) -> Self::Output {
        self + (-other)
    }
}
impl<const N: usize, const D: usize, F: PrimeField> Sub<&Sparse<F, N, D>> for &Sparse<F, N, D> {
    type Output = Sparse<F, N, D>;

    fn sub(self, other: &Sparse<F, N, D>) -> Self::Output {
        self + (-other)
    }
}

/// Equality is defined as equality of the monomials.
impl<const N: usize, const D: usize, F: PrimeField> PartialEq for Sparse<F, N, D> {
    fn eq(&self, other: &Self) -> bool {
        self.monomials == other.monomials
    }
}

impl<const N: usize, const D: usize, F: PrimeField> Eq for Sparse<F, N, D> {}

impl<const N: usize, const D: usize, F: PrimeField> One for Sparse<F, N, D> {
    fn one() -> Self {
        let mut monomials = HashMap::new();
        monomials.insert([0; N], F::one());
        Self { monomials }
    }
}

impl<const N: usize, const D: usize, F: PrimeField> Zero for Sparse<F, N, D> {
    fn is_zero(&self) -> bool {
        self.monomials.len() == 1
            && self.monomials.contains_key(&[0; N])
            && self.monomials[&[0; N]].is_zero()
    }

    fn zero() -> Self {
        let mut monomials = HashMap::new();
        monomials.insert([0; N], F::zero());
        Self { monomials }
    }
}

impl<const N: usize, const D: usize, F: PrimeField> MVPoly<F, N, D> for Sparse<F, N, D> {
    /// Returns the degree of the polynomial.
    ///
    /// The degree of the polynomial is the maximum degree of the monomials
    /// that have a non-zero coefficient.
    ///
    /// # Safety
    ///
    /// The zero polynomial as a degree equals to 0, as the degree of the
    /// constant polynomials. We do use the `unsafe` keyword to warn the user
    /// for this specific case.
    unsafe fn degree(&self) -> usize {
        self.monomials
            .keys()
            .map(|exponents| exponents.iter().sum())
            .max()
            .unwrap_or(0)
    }

    /// Evaluate the polynomial at the vector point `x`.
    ///
    /// This is a dummy implementation. A cache can be used for the monomials to
    /// speed up the computation.
    fn eval(&self, x: &[F; N]) -> F {
        self.monomials
            .iter()
            .map(|(exponents, coeff)| {
                let mut term = F::one();
                for (exp, point) in exponents.iter().zip(x.iter()) {
                    term *= point.pow([*exp as u64]);
                }
                term * coeff
            })
            .sum()
    }

    fn is_constant(&self) -> bool {
        self.monomials.len() == 1 && self.monomials.contains_key(&[0; N])
    }

    fn double(&self) -> Self {
        let monomials: HashMap<[usize; N], F> = self
            .monomials
            .iter()
            .map(|(exponents, coeff)| (*exponents, coeff.double()))
            .collect();
        Self { monomials }
    }

    fn mul_by_scalar(&self, scalar: F) -> Self {
        if scalar.is_zero() {
            Self::zero()
        } else {
            let monomials: HashMap<[usize; N], F> = self
                .monomials
                .iter()
                .map(|(exponents, coeff)| (*exponents, *coeff * scalar))
                .collect();
            Self { monomials }
        }
    }

    /// Generate a random polynomial of maximum degree `max_degree`.
    ///
    /// If `None` is provided as the maximum degree, the polynomial will be
    /// generated with a maximum degree of `D`.
    ///
    /// # Safety
    ///
    /// Marked as unsafe to warn the user to use it with caution and to not
    /// necessarily rely on it for security/randomness in cryptographic
    /// protocols. The user is responsible for providing its own secure
    /// polynomial random generator, if needed.
    ///
    /// For now, the function is only used for testing.
    unsafe fn random<RNG: RngCore>(rng: &mut RNG, max_degree: Option<usize>) -> Self {
        let degree = max_degree.unwrap_or(D);
        // Generating all monomials with degree <= degree^N
        let nested_loops_indices: Vec<Vec<usize>> =
            compute_indices_nested_loop(vec![degree; N], max_degree);
        // Filtering the monomials with degree <= degree
        let exponents: Vec<Vec<usize>> = nested_loops_indices
            .into_iter()
            .filter(|indices| {
                let sum = indices.iter().sum::<usize>();
                sum <= degree
            })
            .collect();
        // We add 10% of zeroes.
        let exponents: Vec<_> = exponents
            .into_iter()
            .filter(|_indices| rng.gen_range(0..10) != 0)
            .collect();
        // Generating random coefficients for the 90%
        let monomials: HashMap<[usize; N], F> = exponents
            .into_iter()
            .map(|indices| {
                let coeff = F::rand(rng);
                (indices.try_into().unwrap(), coeff)
            })
            .collect();
        Self { monomials }
    }

    fn from_variable<Column: Into<usize>>(
        var: Variable<Column>,
        offset_next_row: Option<usize>,
    ) -> Self {
        let Variable { col, row } = var;
        // Manage offset
        if row == CurrOrNext::Next {
            assert!(
                offset_next_row.is_some(),
                "The offset must be provided for the next row"
            );
        }
        let offset = if row == CurrOrNext::Curr {
            0
        } else {
            offset_next_row.unwrap()
        };

        // Build the corresponding monomial
        let var_usize: usize = col.into();
        let idx = offset + var_usize;
        assert!(
            idx < N,
            "Only {N} variables can be used, and {idx} has been given. To get an equivalent mvpoly, you need to increase the number of variables"
        );

        let mut monomials = HashMap::new();
        let exponents: [usize; N] = std::array::from_fn(|i| if i == idx { 1 } else { 0 });
        monomials.insert(exponents, F::one());
        Self { monomials }
    }

    fn is_homogeneous(&self) -> bool {
        self.monomials
            .iter()
            .all(|(exponents, _)| exponents.iter().sum::<usize>() == D)
    }

    // IMPROVEME: powers can be cached
    fn homogeneous_eval(&self, x: &[F; N], u: F) -> F {
        self.monomials
            .iter()
            .map(|(exponents, coeff)| {
                let mut term = F::one();
                for (exp, point) in exponents.iter().zip(x.iter()) {
                    term *= point.pow([*exp as u64]);
                }
                term *= u.pow([D as u64 - exponents.iter().sum::<usize>() as u64]);
                term * coeff
            })
            .sum()
    }

    fn add_monomial(&mut self, exponents: [usize; N], coeff: F) {
        self.monomials
            .entry(exponents)
            .and_modify(|c| *c += coeff)
            .or_insert(coeff);
    }

    fn compute_cross_terms(
        &self,
        eval1: &[F; N],
        eval2: &[F; N],
        u1: F,
        u2: F,
    ) -> HashMap<usize, F> {
        assert!(
            D >= 2,
            "The degree of the polynomial must be greater than 2"
        );
        let mut cross_terms_by_powers_of_r: HashMap<usize, F> = HashMap::new();
        // We iterate over each monomial with their respective coefficient
        // i.e. we do have something like coeff * x_1^d_1 * x_2^d_2 * ... * x_N^d_N
        self.monomials.iter().for_each(|(exponents, coeff)| {
            // "Exponents" contains all powers, even the ones that are 0. We must
            // get rid of them and keep the index to fetch the correct
            // evaluation later
            let non_zero_exponents_with_index: Vec<(usize, &usize)> = exponents
                .iter()
                .enumerate()
                .filter(|(_, &d)| d != 0)
                .collect();
            // coeff = 0 should not happen as we suppose we have a sparse polynomial
            // Therefore, skipping a check
            let non_zero_exponents: Vec<usize> = non_zero_exponents_with_index
                .iter()
                .map(|(_, d)| *d)
                .copied()
                .collect::<Vec<usize>>();
            let monomial_degree = non_zero_exponents.iter().sum::<usize>();
            let u_degree: usize = D - monomial_degree;
            // Will be used to compute the nested sums
            // It returns all the indices i_1, ..., i_k for the sums:
            // Σ_{i_1 = 0}^{n_1} Σ_{i_2 = 0}^{n_2} ... Σ_{i_k = 0}^{n_k}
            let indices = compute_indices_nested_loop(
                non_zero_exponents.iter().map(|d| *d + 1).collect(),
                None,
            );
            for i in 0..=u_degree {
                // Add the binomial from the homogeneisation
                // i.e (u_degree choose i)
                let u_binomial_term = binomial(u_degree, i);
                // Now, we iterate over all the indices i_1, ..., i_k, i.e. we
                // do over the whole sum, and we populate the map depending on
                // the power of r
                indices.iter().for_each(|indices| {
                    let sum_indices = indices.iter().sum::<usize>() + i;
                    // power of r is Σ (n_k - i_k)
                    let power_r: usize = D - sum_indices;

                    // If the sum of the indices is 0 or D, we skip the
                    // computation as the contribution would go in the
                    // evaluation of the polynomial at each evaluation
                    // vectors eval1 and eval2
                    if sum_indices == 0 || sum_indices == D {
                        return;
                    }
                    // Compute
                    // (n_1 choose i_1) * (n_2 choose i_2) * ... * (n_k choose i_k)
                    let binomial_term = indices
                        .iter()
                        .zip(non_zero_exponents.iter())
                        .fold(u_binomial_term, |acc, (i, &d)| acc * binomial(d, *i));
                    let binomial_term = F::from(binomial_term as u64);
                    // Compute the product x_k^i_k
                    // We ignore the power as it comes into account for the
                    // right evaluation.
                    // NB: we could merge both loops, but we keep them separate
                    // for readability
                    let eval_left = indices
                        .iter()
                        .zip(non_zero_exponents_with_index.iter())
                        .fold(F::one(), |acc, (i, (idx, _d))| {
                            acc * eval1[*idx].pow([*i as u64])
                        });
                    // Compute the product x'_k^(n_k - i_k)
                    let eval_right = indices
                        .iter()
                        .zip(non_zero_exponents_with_index.iter())
                        .fold(F::one(), |acc, (i, (idx, d))| {
                            acc * eval2[*idx].pow([(*d - *i) as u64])
                        });
                    // u1^i * u2^(u_degree - i)
                    let u = u1.pow([i as u64]) * u2.pow([(u_degree - i) as u64]);
                    let res = binomial_term * eval_left * eval_right * u;
                    let res = *coeff * res;
                    cross_terms_by_powers_of_r
                        .entry(power_r)
                        .and_modify(|e| *e += res)
                        .or_insert(res);
                })
            }
        });
        cross_terms_by_powers_of_r
    }

    fn compute_cross_terms_scaled(
        &self,
        eval1: &[F; N],
        eval2: &[F; N],
        u1: F,
        u2: F,
        scalar1: F,
        scalar2: F,
    ) -> HashMap<usize, F> {
        assert!(
            D >= 2,
            "The degree of the polynomial must be greater than 2"
        );
        let cross_terms = self.compute_cross_terms(eval1, eval2, u1, u2);

        let mut res: HashMap<usize, F> = HashMap::new();
        cross_terms.iter().for_each(|(power_r, coeff)| {
            res.insert(*power_r, *coeff * scalar1);
        });
        // Small speed-up, avoid going through the whole set of cross-terms if
        // scalar2 is zero
        // In addition to that, it won't compute the homogeneous evaluation,
        // which can be relatively expensive
        if scalar2 != F::zero() {
            cross_terms.iter().for_each(|(power_r, coeff)| {
                res.entry(*power_r + 1)
                    .and_modify(|e| *e += *coeff * scalar2)
                    .or_insert(*coeff * scalar2);
            });
            let eval1_hom = self.homogeneous_eval(eval1, u1);
            res.entry(1)
                .and_modify(|e| *e += eval1_hom * scalar2)
                .or_insert(eval1_hom * scalar2);
        }
        // Small speed-up, avoid computing the homogeneous evaluation if scalar1
        // is zero
        if scalar1 != F::zero() {
            let eval2_hom = self.homogeneous_eval(eval2, u2);
            res.entry(D)
                .and_modify(|e| *e += eval2_hom * scalar1)
                .or_insert(eval2_hom * scalar1);
        } else {
            res.entry(D).or_insert(F::zero());
        }
        res
    }

    fn modify_monomial(&mut self, exponents: [usize; N], coeff: F) {
        self.monomials
            .entry(exponents)
            .and_modify(|c| *c = coeff)
            .or_insert(coeff);
    }

    fn is_multilinear(&self) -> bool {
        self.monomials
            .iter()
            .all(|(exponents, _)| exponents.iter().all(|&d| d <= 1))
    }
}

impl<const N: usize, const D: usize, F: PrimeField> From<prime::Dense<F, N, D>>
    for Sparse<F, N, D>
{
    fn from(dense: prime::Dense<F, N, D>) -> Self {
        let mut prime_gen = PrimeNumberGenerator::new();
        let primes = prime_gen.get_first_nth_primes(N);
        let mut monomials = HashMap::new();
        let normalized_indices = prime::Dense::<F, N, D>::compute_normalized_indices();
        dense.iter().enumerate().for_each(|(i, coeff)| {
            if *coeff != F::zero() {
                let mut exponents = [0; N];
                let inv_idx = normalized_indices[i];
                let prime_decomposition_of_index = naive_prime_factors(inv_idx, &mut prime_gen);
                prime_decomposition_of_index
                    .into_iter()
                    .for_each(|(prime, exp)| {
                        let inv_prime_idx = primes.iter().position(|&p| p == prime).unwrap();
                        exponents[inv_prime_idx] = exp;
                    });
                monomials.insert(exponents, *coeff);
            }
        });
        Self { monomials }
    }
}

impl<F: PrimeField, const N: usize, const D: usize> From<F> for Sparse<F, N, D> {
    fn from(value: F) -> Self {
        let mut result = Self::zero();
        result.modify_monomial([0; N], value);
        result
    }
}

impl<F: PrimeField, const N: usize, const D: usize, const M: usize, const D_PRIME: usize>
    From<Sparse<F, N, D>> for Result<Sparse<F, M, D_PRIME>, String>
{
    fn from(poly: Sparse<F, N, D>) -> Result<Sparse<F, M, D_PRIME>, String> {
        if M < N {
            return Err(format!(
                "The final number of variables {M} must be greater than {N}"
            ));
        }
        if D_PRIME < D {
            return Err(format!(
                "The final degree {D_PRIME} must be greater than initial degree {D}"
            ));
        }
        let mut monomials = HashMap::new();
        poly.monomials.iter().for_each(|(exponents, coeff)| {
            let mut new_exponents = [0; M];
            new_exponents[0..N].copy_from_slice(&exponents[0..N]);
            monomials.insert(new_exponents, *coeff);
        });
        Ok(Sparse { monomials })
    }
}
