//! Multivariate polynomial
//! See [these notes](https://hackmd.io/@dannywillems/SyHar7p5A) for more context.

use std::ops::Add;

use ark_ff::Field;
use num_integer::binomial;

use crate::utils::{naive_prime_factors, PrimeNumberGenerator};

pub fn dimension_of_multivariate_polynomial<const N: usize, const D: usize>() -> usize {
    binomial(N + D, D)
}

/// Represents a multivariate polynomial of degree `D` in `N` variables.
/// The natural representation is the coefficients given in the monomial basis.
pub struct MVPoly<F: Field, const N: usize, const D: usize> {
    coeff: Vec<F>,
}

impl<F: Field, const N: usize, const D: usize> MVPoly<F, N, D> {
    pub fn new() -> Self {
        MVPoly {
            coeff: vec![F::zero(); dimension_of_multivariate_polynomial::<N, D>()],
        }
    }

    pub fn from_coeffs(coeff: Vec<F>) -> Self {
        MVPoly { coeff }
    }

    pub fn len(&self) -> usize {
        self.coeff.len()
    }

    pub fn is_empty(&self) -> bool {
        self.coeff.is_empty()
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
    pub fn normalized_indices(&self) -> Vec<usize> {
        let mut normalized_indices = vec![1; self.len()];
        let mut prime_gen = PrimeNumberGenerator::new();
        let primes = prime_gen.get_first_nth_primes(N);
        let max_index = primes[N - 1].pow(D as u32);
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
}

impl<F: Field, const N: usize, const D: usize> Default for MVPoly<F, N, D> {
    fn default() -> Self {
        MVPoly::new()
    }
}

// Addition
impl<F: Field, const N: usize, const D: usize> Add for MVPoly<F, N, D> {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        let mut result = MVPoly::new();
        for i in 0..self.len() {
            result.coeff[i] = self.coeff[i] + other.coeff[i];
        }
        result
    }
}

impl<F: Field, const N: usize, const D: usize> Add<&MVPoly<F, N, D>> for MVPoly<F, N, D> {
    type Output = MVPoly<F, N, D>;

    fn add(self, other: &MVPoly<F, N, D>) -> MVPoly<F, N, D> {
        let mut result = MVPoly::new();
        for i in 0..self.len() {
            result.coeff[i] = self.coeff[i] + other.coeff[i];
        }
        result
    }
}

impl<F: Field, const N: usize, const D: usize> Add<MVPoly<F, N, D>> for &MVPoly<F, N, D> {
    type Output = MVPoly<F, N, D>;

    fn add(self, other: MVPoly<F, N, D>) -> MVPoly<F, N, D> {
        let mut result = MVPoly::new();
        for i in 0..self.len() {
            result.coeff[i] = self.coeff[i] + other.coeff[i];
        }
        result
    }
}

impl<F: Field, const N: usize, const D: usize> Add<&MVPoly<F, N, D>> for &MVPoly<F, N, D> {
    type Output = MVPoly<F, N, D>;

    fn add(self, other: &MVPoly<F, N, D>) -> MVPoly<F, N, D> {
        let mut result = MVPoly::new();
        for i in 0..self.len() {
            result.coeff[i] = self.coeff[i] + other.coeff[i];
        }
        result
    }
}
// TODO: implement From/To Expr<F, Column>
