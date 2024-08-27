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
use num_integer::binomial;
use o1_utils::FieldHelpers;
use rand::RngCore;
use std::ops::{Index, IndexMut};

use crate::utils::{
    compute_all_two_factors_decomposition, naive_prime_factors, PrimeNumberGenerator,
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

impl<F: PrimeField, const N: usize, const D: usize> Dense<F, N, D> {
    pub fn new() -> Self {
        let normalized_indices = Self::compute_normalized_indices();
        Dense {
            coeff: vec![F::zero(); Self::dimension()],
            normalized_indices,
        }
    }

    pub fn random<RNG: RngCore>(rng: &mut RNG) -> Self {
        let normalized_indices = Self::compute_normalized_indices();
        let coeff = normalized_indices
            .iter()
            .map(|_| F::rand(rng))
            .collect::<Vec<F>>();
        Dense {
            coeff,
            normalized_indices,
        }
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

    /// Returns `true` if the polynomial is homoegenous of degree `d`
    pub fn is_homogeneous(&self) -> bool {
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

    pub fn double(&self) -> Self {
        let mut result = Dense::zero();
        for i in 0..self.coeff.len() {
            result.coeff[i] = self.coeff[i].double();
        }
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
        let mut result = Dense::new();
        for i in 0..self.coeff.len() {
            result.coeff[i] = self.coeff[i] + other.coeff[i];
        }
        result
    }
}

impl<F: PrimeField, const N: usize, const D: usize> Add<&Dense<F, N, D>> for Dense<F, N, D> {
    type Output = Dense<F, N, D>;

    fn add(self, other: &Dense<F, N, D>) -> Dense<F, N, D> {
        let mut result = Dense::new();
        for i in 0..self.coeff.len() {
            result.coeff[i] = self.coeff[i] + other.coeff[i];
        }
        result
    }
}

impl<F: PrimeField, const N: usize, const D: usize> Add<Dense<F, N, D>> for &Dense<F, N, D> {
    type Output = Dense<F, N, D>;

    fn add(self, other: Dense<F, N, D>) -> Dense<F, N, D> {
        let mut result = Dense::new();
        for i in 0..self.coeff.len() {
            result.coeff[i] = self.coeff[i] + other.coeff[i];
        }
        result
    }
}

impl<F: PrimeField, const N: usize, const D: usize> Add<&Dense<F, N, D>> for &Dense<F, N, D> {
    type Output = Dense<F, N, D>;

    fn add(self, other: &Dense<F, N, D>) -> Dense<F, N, D> {
        let mut result = Dense::new();
        for i in 0..self.coeff.len() {
            result.coeff[i] = self.coeff[i] + other.coeff[i];
        }
        result
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
        let mut result = Dense::new();
        for i in 0..self.coeff.len() {
            result.coeff[i] = self.coeff[i] - other.coeff[i];
        }
        result
    }
}

impl<F: PrimeField, const N: usize, const D: usize> Sub<Dense<F, N, D>> for &Dense<F, N, D> {
    type Output = Dense<F, N, D>;

    fn sub(self, other: Dense<F, N, D>) -> Dense<F, N, D> {
        let mut result = Dense::new();
        for i in 0..self.coeff.len() {
            result.coeff[i] = self.coeff[i] - other.coeff[i];
        }
        result
    }
}

impl<F: PrimeField, const N: usize, const D: usize> Sub<&Dense<F, N, D>> for &Dense<F, N, D> {
    type Output = Dense<F, N, D>;

    fn sub(self, other: &Dense<F, N, D>) -> Dense<F, N, D> {
        let mut result = Dense::new();
        for i in 0..self.coeff.len() {
            result.coeff[i] = self.coeff[i] - other.coeff[i];
        }
        result
    }
}

// Negation
impl<F: PrimeField, const N: usize, const D: usize> Neg for Dense<F, N, D> {
    type Output = Self;

    fn neg(self) -> Self::Output {
        let mut result = Dense::new();
        for i in 0..self.coeff.len() {
            result.coeff[i] = -self.coeff[i];
        }
        result
    }
}

impl<F: PrimeField, const N: usize, const D: usize> Neg for &Dense<F, N, D> {
    type Output = Dense<F, N, D>;

    fn neg(self) -> Self::Output {
        let mut result = Dense::new();
        for i in 0..self.coeff.len() {
            result.coeff[i] = -self.coeff[i];
        }
        result
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

impl<F: PrimeField, const N: usize, const D: usize> Dense<F, N, D> {}
// TODO: implement From/To Expr<F, Column>
