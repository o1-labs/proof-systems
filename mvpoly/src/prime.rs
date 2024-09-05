//! Multivariate polynomial dense representation using prime numbers
//!
//! First, we start by attributing a different prime number for each variable.
//! For instance, for `F^{<=2}[X_{1}, X_{2}]`, we assign `X_{1}` to `2`
//! and $X_{2}$ to $3$.
//! From there, we note `X_{1} X_{2}` as the value `6`, `X_{1}^2` as `4`, `X_{2}^2`
//! as 9. The constant is `1`.
//!
//! From there, we represent our polynomial coefficients in a sparse list. Some
//! cells, noted `NA`, won't be used for certain vector spaces.
//!
//! For instance, `X_{1} + X_{2}` will be represented as:
//! ```text
//! [0,   1,   1,   0,    0,   0,    0,    0,    0]
//!  |    |    |    |     |    |     |     |     |
//!  1    2    3    4     5    6     7     8     9
//!  |    |    |    |     |    |     |     |     |
//!  cst  X1  X2   X1^2   NA  X1*X2  NA   NA    X2^2
//! ```
//!
//! and the polynomial `42 X_{1} + 3 X_{1} X_{2} + 14 X_{2}^2` will be represented
//! as
//!
//! ```text
//! [0,  42,   1,   0,    0,   3,    0,    0,    14]
//!  |    |    |    |     |    |     |     |     |
//!  1    2    3    4     5    6     7     8     9
//!  |    |    |    |     |    |     |     |     |
//!  cst  X1  X2   X1^2   NA  X1*X2  NA   NA    X2^2
//! ```
//!
//! Adding two polynomials in this base is pretty straightforward: we simply add the
//! coefficients of the two lists.
//!
//! Multiplication is not more complicated.
//! To compute the result of $P_{1} * P_{2}$, the value of index $i$ will be the sum
//! of the decompositions.
//!
//! For instance, if we take `P_{1}(X_{1}) = 2 X_{1} + X_{2}` and `P_{2}(X_{1},
//! X_{2}) = X_{2} + 3`, the expected product is
//! `P_{3}(X_{1}, X_{2}) = (2 X_{1} + X_{2}) * (X_{2} + 3) = 2 X_{1} X_{2} + 6
//! X_{1} + 3 X_{2} + X_{2}^2`
//!
//! Given in the representation above, we have:
//!
//! ```text
//! For P_{1}:
//!
//! [0,   2,   1,   0,    0,   0,    0,    0,    0]
//!  |    |    |    |     |    |     |     |     |
//!  1    2    3    4     5    6     7     8     9
//!  |    |    |    |     |    |     |     |     |
//!  cst  X1  X2   X1^2   NA  X1*X2  NA   NA    X2^2
//!
//! ```
//!
//! ```text
//! For P_{2}:
//!
//! [3,   0,   1,   0,    0,   0,    0,    0,    0]
//!  |    |    |    |     |    |     |     |     |
//!  1    2    3    4     5    6     7     8     9
//!  |    |    |    |     |    |     |     |     |
//!  cst  X1  X2   X1^2   NA  X1*X2  NA   NA    X2^2
//!
//! ```
//!
//!
//! ```text
//! For P_{3}:
//!
//! [0,   6,   3,   0,    0,   2,    0,    0,    1]
//!  |    |    |    |     |    |     |     |     |
//!  1    2    3    4     5    6     7     8     9
//!  |    |    |    |     |    |     |     |     |
//!  cst  X1  X2   X1^2   NA  X1*X2  NA   NA    X2^2
//!
//! ```
//!
//! To compute `P_{3}`, we get iterate over an empty list of $9$ elements which will
//! define `P_{3}`.
//!
//! For index `1`, we multiply `P_{1}[1]` and `P_{1}[1]`.
//!
//! FOr index $2$, the only way to get this index is by fetching $2$ in each list.
//! Therefore, we do `P_{1}[2] P_{2}[1] + P_{2}[2] * P_{1}[1] = 2 * 3 + 0 * 0 = 6`.
//!
//! For index `3`, same than for `2`.
//!
//! For index `4`, we have `4 = 2 * 2`, therefore, we multiply `P_{1}[2]` and `P_{2}[2]`
//!
//! For index `6`, we have `6 = 2 * 3` and `6 = 3 * 2`, which are the prime
//! decompositions of $6$. Therefore we sum `P_{1}[2] * P_{2}[3]` and `P_{2}[2] *
//! P_{1}[3]`.
//!
//! For index $9$, we have $9 = 3 * 3$, therefore we do the same than for $4$.
//!
//! This can be generalized.
//!
//! The algorithm is as follow:
//! - for each cell `j`:
//!     - if `j` is prime, compute `P_{1}[j] P_{2}[1] + P_{2}[j] P_{1}[1]`
//!     - else:
//!         - take the prime decompositions of `j` (and their permutations).
//!         - for each decomposition, compute the product
//!         - sum
//!
//!
//! #### Other examples degree $2$ with 3 variables.
//!
//! ```math
//! \begin{align}
//! $\mathbb{F}^{\le 2}[X_{1}, X_{2}, X_{3}] = \{
//!         & \, a_{0} + \\
//!         & \, a_{1} X_{1} + \\
//!         & \, a_{2} X_{2} + \\
//!         & \, a_{3} X_{3} + \\
//!         & \, a_{4} X_{1} X_{2} + \\
//!         & \, a_{5} X_{2} X_{3} + \\
//!         & \, a_{6} X_{1} X_{3} + \\
//!         & \, a_{7} X_{1}^2 + \\
//!         & \, a_{8} X_{2}^2 + \\
//!         & \, a_{9} X_{3}^2 \, | \, a_{i} \in \mathbb{F}
//!         \}
//! \end{align}
//! ```
//!
//! We assign:
//!
//! - `X_{1} = 2`
//! - `X_{2} = 3`
//! - `X_{3} = 5`
//!
//! And therefore, we have:
//! - `X_{1}^2 = 4`
//! - `X_{1} X_{2} = 6`
//! - `X_{1} X_{3} = 10`
//! - `X_{2}^2 = 9`
//! - `X_{2} X_{3} = 15`
//! - `X_{3}^2 = 25`
//!
//! We have an array with 25 indices, even though we need 10 elements only.

use std::{
    collections::HashMap,
    fmt::{Debug, Formatter, Result},
    ops::{Add, Mul, Neg, Sub},
};

use ark_ff::{One, PrimeField, Zero};
use kimchi::circuits::{
    expr::{
        ChallengeTerm, ConstantExpr, ConstantExprInner, ConstantTerm, Expr, ExprInner, Operations,
        Variable,
    },
    gate::CurrOrNext,
};
use num_integer::binomial;
use o1_utils::FieldHelpers;
use rand::RngCore;
use std::ops::{Index, IndexMut};

use crate::{
    utils::{compute_all_two_factors_decomposition, naive_prime_factors, PrimeNumberGenerator},
    MVPoly,
};

/// Represents a multivariate polynomial of degree less than `D` in `N` variables.
/// The representation is dense, i.e., all coefficients are stored.
/// The polynomial is represented as a vector of coefficients, where the index
/// of the coefficient corresponds to the index of the monomial.
/// A mapping between the index and the prime decomposition of the monomial is
/// stored in `normalized_indices`.
#[derive(Clone)]
pub struct Dense<F: PrimeField, const N: usize, const D: usize> {
    coeff: Vec<F>,
    // keeping track of the indices of the monomials that are normalized
    // to avoid recomputing them
    // FIXME: this should be stored somewhere else; we should not have it for
    // each polynomial
    normalized_indices: Vec<usize>,
}

impl<F: PrimeField, const N: usize, const D: usize> Index<usize> for Dense<F, N, D> {
    type Output = F;

    fn index(&self, index: usize) -> &Self::Output {
        &self.coeff[index]
    }
}

impl<F: PrimeField, const N: usize, const D: usize> IndexMut<usize> for Dense<F, N, D> {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.coeff[index]
    }
}

impl<F: PrimeField, const N: usize, const D: usize> Zero for Dense<F, N, D> {
    fn is_zero(&self) -> bool {
        self.coeff.iter().all(|c| c.is_zero())
    }

    fn zero() -> Self {
        Dense {
            coeff: vec![F::zero(); Self::dimension()],
            normalized_indices: Self::compute_normalized_indices(),
        }
    }
}

impl<F: PrimeField, const N: usize, const D: usize> One for Dense<F, N, D> {
    fn one() -> Self {
        let mut result = Dense::zero();
        result.coeff[0] = F::one();
        result
    }
}

impl<F: PrimeField, const N: usize, const D: usize> MVPoly<F, N, D> for Dense<F, N, D> {
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
        let mut prime_gen = PrimeNumberGenerator::new();
        let normalized_indices = Self::compute_normalized_indices();
        // Different cases to avoid complexity in the case no maximum degree is
        // provided
        let coeff = if let Some(max_degree) = max_degree {
            normalized_indices
                .iter()
                .map(|idx| {
                    let degree = naive_prime_factors(*idx, &mut prime_gen)
                        .iter()
                        .fold(0, |acc, (_, d)| acc + d);
                    if degree > max_degree {
                        F::zero()
                    } else {
                        F::rand(rng)
                    }
                })
                .collect::<Vec<F>>()
        } else {
            normalized_indices.iter().map(|_| F::rand(rng)).collect()
        };
        Dense {
            coeff,
            normalized_indices,
        }
    }

    fn is_constant(&self) -> bool {
        self.coeff.iter().skip(1).all(|c| c.is_zero())
    }

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
        if self.is_constant() {
            return 0;
        }
        let mut prime_gen = PrimeNumberGenerator::new();
        self.coeff.iter().enumerate().fold(1, |acc, (i, c)| {
            if *c != F::zero() {
                let decomposition_of_i =
                    naive_prime_factors(self.normalized_indices[i], &mut prime_gen);
                let monomial_degree = decomposition_of_i.iter().fold(0, |acc, (_, d)| acc + d);
                acc.max(monomial_degree)
            } else {
                acc
            }
        })
    }

    fn double(&self) -> Self {
        let coeffs = self.coeff.iter().map(|c| c.double()).collect();
        Self::from_coeffs(coeffs)
    }

    fn mul_by_scalar(&self, c: F) -> Self {
        let coeffs = self.coeff.iter().map(|coef| *coef * c).collect();
        Self::from_coeffs(coeffs)
    }

    /// Evaluate the polynomial at the vector point `x`.
    ///
    /// This is a dummy implementation. A cache can be used for the monomials to
    /// speed up the computation.
    fn eval(&self, x: &[F; N]) -> F {
        let mut prime_gen = PrimeNumberGenerator::new();
        let primes = prime_gen.get_first_nth_primes(N);
        self.coeff
            .iter()
            .enumerate()
            .fold(F::zero(), |acc, (i, c)| {
                if i == 0 {
                    acc + c
                } else {
                    let normalized_index = self.normalized_indices[i];
                    // IMPROVEME: we should keep the prime decomposition somewhere.
                    // It can be precomputed for a few multi-variate polynomials
                    // vector space
                    let prime_decomposition = naive_prime_factors(normalized_index, &mut prime_gen);
                    let mut monomial = F::one();
                    prime_decomposition.iter().for_each(|(p, d)| {
                        // IMPROVEME: we should keep the inverse indices
                        let inv_p = primes.iter().position(|&x| x == *p).unwrap();
                        let x_p = x[inv_p].pow([*d as u64]);
                        monomial *= x_p;
                    });
                    acc + *c * monomial
                }
            })
    }

    fn is_homogeneous(&self) -> bool {
        let normalized_indices = self.normalized_indices.clone();
        let mut prime_gen = PrimeNumberGenerator::new();
        let is_homogeneous = normalized_indices
            .iter()
            .zip(self.coeff.clone())
            .all(|(idx, c)| {
                let decomposition_of_i = naive_prime_factors(*idx, &mut prime_gen);
                let monomial_degree = decomposition_of_i.iter().fold(0, |acc, (_, d)| acc + d);
                monomial_degree == D || c == F::zero()
            });
        is_homogeneous
    }
}

impl<F: PrimeField, const N: usize, const D: usize> Dense<F, N, D> {
    pub fn new() -> Self {
        let normalized_indices = Self::compute_normalized_indices();
        Dense {
            coeff: vec![F::zero(); Self::dimension()],
            normalized_indices,
        }
    }
    pub fn iter(&self) -> impl Iterator<Item = &F> {
        self.coeff.iter()
    }

    pub fn dimension() -> usize {
        binomial(N + D, D)
    }

    pub fn from_coeffs(coeff: Vec<F>) -> Self {
        let normalized_indices = Self::compute_normalized_indices();
        Dense {
            coeff,
            normalized_indices,
        }
    }

    pub fn from_variable<C: Into<usize>>(var: C) -> Self {
        let mut res = Self::zero();
        let mut prime_gen = PrimeNumberGenerator::new();
        let primes = prime_gen.get_first_nth_primes(N);
        let var_usize: usize = var.into();
        assert!(primes.contains(&var_usize), "The usize representation of the variable must be a prime number, and unique for each variable");
        let inv_var = res
            .normalized_indices
            .iter()
            .position(|&x| x == var_usize)
            .unwrap();
        res[inv_var] = F::one();
        res
    }

    pub fn number_of_variables(&self) -> usize {
        N
    }

    pub fn maximum_degree(&self) -> usize {
        D
    }

    /// Output example for N = 2 and D = 2:
    /// ```text
    /// - 0 -> 1
    /// - 1 -> 2
    /// - 2 -> 3
    /// - 3 -> 4
    /// - 4 -> 6
    /// - 5 -> 9
    /// ```
    pub fn compute_normalized_indices() -> Vec<usize> {
        let mut normalized_indices = vec![1; Self::dimension()];
        let mut prime_gen = PrimeNumberGenerator::new();
        let primes = prime_gen.get_first_nth_primes(N);
        let max_index = primes[N - 1].checked_pow(D as u32);
        let max_index = max_index.expect("Overflow in computing the maximum index");
        let mut j = 0;
        (1..=max_index).for_each(|i| {
            let prime_decomposition_of_index = naive_prime_factors(i, &mut prime_gen);
            let is_valid_decomposition = prime_decomposition_of_index
                .iter()
                .all(|(p, _)| primes.contains(p));
            let monomial_degree = prime_decomposition_of_index
                .iter()
                .fold(0, |acc, (_, d)| acc + d);
            let is_valid_decomposition = is_valid_decomposition && monomial_degree <= D;
            if is_valid_decomposition {
                normalized_indices[j] = i;
                j += 1;
            }
        });
        normalized_indices
    }

    pub fn increase_degree<const D_PRIME: usize>(&self) -> Dense<F, N, D_PRIME> {
        assert!(D <= D_PRIME, "The degree of the target polynomial must be greater or equal to the degree of the source polynomial");
        let mut result: Dense<F, N, D_PRIME> = Dense::zero();
        let dst_normalized_indices = Dense::<F, N, D_PRIME>::compute_normalized_indices();
        let src_normalized_indices = Dense::<F, N, D>::compute_normalized_indices();
        src_normalized_indices
            .iter()
            .enumerate()
            .for_each(|(i, idx)| {
                // IMPROVEME: should be computed once
                let inv_idx = dst_normalized_indices
                    .iter()
                    .position(|&x| x == *idx)
                    .unwrap();
                result[inv_idx] = self[i];
            });
        result
    }
}

impl<F: PrimeField, const N: usize, const D: usize> Default for Dense<F, N, D> {
    fn default() -> Self {
        Dense::new()
    }
}

// Addition
impl<F: PrimeField, const N: usize, const D: usize> Add for Dense<F, N, D> {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        let coeffs = self
            .coeff
            .iter()
            .zip(other.coeff.iter())
            .map(|(a, b)| *a + *b)
            .collect();
        Self::from_coeffs(coeffs)
    }
}

impl<F: PrimeField, const N: usize, const D: usize> Add<&Dense<F, N, D>> for Dense<F, N, D> {
    type Output = Dense<F, N, D>;

    fn add(self, other: &Dense<F, N, D>) -> Dense<F, N, D> {
        let coeffs = self
            .coeff
            .iter()
            .zip(other.coeff.iter())
            .map(|(a, b)| *a + *b)
            .collect();
        Self::from_coeffs(coeffs)
    }
}

impl<F: PrimeField, const N: usize, const D: usize> Add<Dense<F, N, D>> for &Dense<F, N, D> {
    type Output = Dense<F, N, D>;

    fn add(self, other: Dense<F, N, D>) -> Dense<F, N, D> {
        let coeffs = self
            .coeff
            .iter()
            .zip(other.coeff.iter())
            .map(|(a, b)| *a + *b)
            .collect();
        Dense::from_coeffs(coeffs)
    }
}

impl<F: PrimeField, const N: usize, const D: usize> Add<&Dense<F, N, D>> for &Dense<F, N, D> {
    type Output = Dense<F, N, D>;

    fn add(self, other: &Dense<F, N, D>) -> Dense<F, N, D> {
        let coeffs = self
            .coeff
            .iter()
            .zip(other.coeff.iter())
            .map(|(a, b)| *a + *b)
            .collect();
        Dense::from_coeffs(coeffs)
    }
}

// Subtraction
impl<F: PrimeField, const N: usize, const D: usize> Sub for Dense<F, N, D> {
    type Output = Self;

    fn sub(self, other: Self) -> Self {
        let mut result = Dense::new();
        for i in 0..self.coeff.len() {
            result.coeff[i] = self.coeff[i] - other.coeff[i];
        }
        result
    }
}

impl<F: PrimeField, const N: usize, const D: usize> Sub<&Dense<F, N, D>> for Dense<F, N, D> {
    type Output = Dense<F, N, D>;

    fn sub(self, other: &Dense<F, N, D>) -> Dense<F, N, D> {
        let coeffs = self
            .coeff
            .iter()
            .zip(other.coeff.iter())
            .map(|(a, b)| *a - *b)
            .collect();
        Dense::from_coeffs(coeffs)
    }
}

impl<F: PrimeField, const N: usize, const D: usize> Sub<Dense<F, N, D>> for &Dense<F, N, D> {
    type Output = Dense<F, N, D>;

    fn sub(self, other: Dense<F, N, D>) -> Dense<F, N, D> {
        let coeffs = self
            .coeff
            .iter()
            .zip(other.coeff.iter())
            .map(|(a, b)| *a - *b)
            .collect();
        Dense::from_coeffs(coeffs)
    }
}

impl<F: PrimeField, const N: usize, const D: usize> Sub<&Dense<F, N, D>> for &Dense<F, N, D> {
    type Output = Dense<F, N, D>;

    fn sub(self, other: &Dense<F, N, D>) -> Dense<F, N, D> {
        let coeffs = self
            .coeff
            .iter()
            .zip(other.coeff.iter())
            .map(|(a, b)| *a - *b)
            .collect();
        Dense::from_coeffs(coeffs)
    }
}

// Negation
impl<F: PrimeField, const N: usize, const D: usize> Neg for Dense<F, N, D> {
    type Output = Self;

    fn neg(self) -> Self::Output {
        let coeffs = self.coeff.iter().map(|c| -*c).collect();
        Self::from_coeffs(coeffs)
    }
}

impl<F: PrimeField, const N: usize, const D: usize> Neg for &Dense<F, N, D> {
    type Output = Dense<F, N, D>;

    fn neg(self) -> Self::Output {
        let coeffs = self.coeff.iter().map(|c| -*c).collect();
        Dense::from_coeffs(coeffs)
    }
}

// Multiplication
impl<F: PrimeField, const N: usize, const D: usize> Mul<Dense<F, N, D>> for Dense<F, N, D> {
    type Output = Self;

    fn mul(self, other: Self) -> Self {
        let mut cache = HashMap::new();
        let mut prime_gen = PrimeNumberGenerator::new();
        let mut result = vec![];
        (0..self.coeff.len()).for_each(|i| {
            let mut sum = F::zero();
            let normalized_index = self.normalized_indices[i];
            let two_factors_decomposition =
                compute_all_two_factors_decomposition(normalized_index, &mut cache, &mut prime_gen);
            two_factors_decomposition.iter().for_each(|(a, b)| {
                // FIXME: we should keep the inverse normalized indices
                let inv_a = self
                    .normalized_indices
                    .iter()
                    .position(|&x| x == *a)
                    .unwrap();
                let inv_b = self
                    .normalized_indices
                    .iter()
                    .position(|&x| x == *b)
                    .unwrap();
                let a_coeff = self.coeff[inv_a];
                let b_coeff = other.coeff[inv_b];
                let product = a_coeff * b_coeff;
                sum += product;
            });
            result.push(sum);
        });
        Self::from_coeffs(result)
    }
}

impl<F: PrimeField, const N: usize, const D: usize> PartialEq for Dense<F, N, D> {
    fn eq(&self, other: &Self) -> bool {
        self.coeff == other.coeff
    }
}

impl<F: PrimeField, const N: usize, const D: usize> Eq for Dense<F, N, D> {}

impl<F: PrimeField, const N: usize, const D: usize> Debug for Dense<F, N, D> {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        let mut prime_gen = PrimeNumberGenerator::new();
        self.coeff.iter().enumerate().for_each(|(i, c)| {
            let normalized_idx = self.normalized_indices[i];
            if normalized_idx == 1 {
                write!(f, "{}", c.to_biguint()).unwrap();
            } else {
                let prime_decomposition = naive_prime_factors(normalized_idx, &mut prime_gen);
                write!(f, "{}", c.to_biguint()).unwrap();
                prime_decomposition.iter().for_each(|(p, d)| {
                    // FIXME: not correct
                    let inv_p = self
                        .normalized_indices
                        .iter()
                        .position(|&x| x == *p)
                        .unwrap();
                    if *d > 1 {
                        write!(f, "x_{}^{}", inv_p, d).unwrap();
                    } else {
                        write!(f, "x_{}", inv_p).unwrap();
                    }
                });
            }
            if i != self.coeff.len() - 1 {
                write!(f, " + ").unwrap();
            }
        });
        Ok(())
    }
}

impl<F: PrimeField, const N: usize, const D: usize> From<F> for Dense<F, N, D> {
    fn from(value: F) -> Self {
        let mut result = Self::zero();
        result.coeff[0] = value;
        result
    }
}

impl<F: PrimeField, const N: usize, const D: usize> From<ConstantExprInner<F>> for Dense<F, N, D> {
    fn from(expr: ConstantExprInner<F>) -> Self {
        match expr {
            // The unimplemented methods might be implemented in the future if
            // we move to the challenge into the type of the constant
            // terms/expressions
            // Unrolling for visibility
            ConstantExprInner::Challenge(ChallengeTerm::Alpha) => {
                unimplemented!("The challenge alpha is not supposed to be used in this context")
            }
            ConstantExprInner::Challenge(ChallengeTerm::Beta) => {
                unimplemented!("The challenge beta is not supposed to be used in this context")
            }
            ConstantExprInner::Challenge(ChallengeTerm::Gamma) => {
                unimplemented!("The challenge gamma is not supposed to be used in this context")
            }
            ConstantExprInner::Challenge(ChallengeTerm::JointCombiner) => {
                unimplemented!(
                    "The challenge joint combiner is not supposed to be used in this context"
                )
            }
            ConstantExprInner::Constant(ConstantTerm::EndoCoefficient) => {
                unimplemented!(
                    "The constant EndoCoefficient is not supposed to be used in this context"
                )
            }
            ConstantExprInner::Constant(ConstantTerm::Mds {
                row: _row,
                col: _col,
            }) => {
                unimplemented!("The constant Mds is not supposed to be used in this context")
            }
            ConstantExprInner::Constant(ConstantTerm::Literal(c)) => Dense::from(c),
        }
    }
}

impl<F: PrimeField, const N: usize, const D: usize> From<Operations<ConstantExprInner<F>>>
    for Dense<F, N, D>
{
    fn from(op: Operations<ConstantExprInner<F>>) -> Self {
        use kimchi::circuits::expr::Operations::*;
        match op {
            Atom(op_const) => Self::from(op_const),
            Add(c1, c2) => Self::from(*c1) + Self::from(*c2),
            Sub(c1, c2) => Self::from(*c1) - Self::from(*c2),
            Mul(c1, c2) => Self::from(*c1) * Self::from(*c2),
            Square(c) => Self::from(*c.clone()) * Self::from(*c),
            Double(c1) => Self::from(*c1).double(),
            Pow(c, e) => {
                // FIXME: dummy implementation
                let p = Dense::from(*c);
                let mut result = p.clone();
                for _ in 0..e {
                    result = result.clone() * p.clone();
                }
                result
            }
            Cache(_c, _) => {
                unimplemented!("The module prime is supposed to be used for generic multivariate expressions, not tied to a specific use case like Kimchi with this constructor")
            }
            IfFeature(_c, _t, _f) => {
                unimplemented!("The module prime is supposed to be used for generic multivariate expressions, not tied to a specific use case like Kimchi with this constructor")
            }
        }
    }
}

impl<Column: Into<usize>, F: PrimeField, const N: usize, const D: usize>
    From<Expr<ConstantExpr<F>, Column>> for Dense<F, N, D>
{
    fn from(expr: Expr<ConstantExpr<F>, Column>) -> Self {
        // This is a dummy implementation
        // TODO: Implement the actual conversion logic
        use kimchi::circuits::expr::Operations::*;

        match expr {
            Atom(op_const) => {
                match op_const {
                    ExprInner::UnnormalizedLagrangeBasis(_) => {
                        unimplemented!("Not used in this context")
                    }
                    ExprInner::VanishesOnZeroKnowledgeAndPreviousRows => {
                        unimplemented!("Not used in this context")
                    }
                    ExprInner::Constant(c) => Self::from(c),
                    ExprInner::Cell(Variable { col, row }) => {
                        assert_eq!(row, CurrOrNext::Curr, "Only current row is supported for now. You cannot reference the next row");
                        Self::from_variable(col)
                    }
                }
            }
            Add(e1, e2) => {
                let p1 = Dense::from(*e1);
                let p2 = Dense::from(*e2);
                p1 + p2
            }
            Sub(e1, e2) => {
                let p1 = Dense::from(*e1);
                let p2 = Dense::from(*e2);
                p1 - p2
            }
            Mul(e1, e2) => {
                let p1 = Dense::from(*e1);
                let p2 = Dense::from(*e2);
                p1 * p2
            }
            Double(p) => {
                let p = Dense::from(*p);
                p.double()
            }
            Square(p) => {
                let p = Dense::from(*p);
                p.clone() * p.clone()
            }
            Pow(c, e) => {
                // FIXME: dummy implementation
                let p = Dense::from(*c);
                let mut result = p.clone();
                for _ in 0..e {
                    result = result.clone() * p.clone();
                }
                result
            }
            Cache(_c, _) => {
                unimplemented!("The module prime is supposed to be used for generic multivariate expressions, not tied to a specific use case like Kimchi with this constructor")
            }
            IfFeature(_c, _t, _f) => {
                unimplemented!("The module prime is supposed to be used for generic multivariate expressions, not tied to a specific use case like Kimchi with this constructor")
            }
        }
    }
}

// TODO: implement From/To Expr<F, Column>
