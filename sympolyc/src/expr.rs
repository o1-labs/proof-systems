//! Multivariate polynomial
//! See [these notes](https://hackmd.io/@dannywillems/SyHar7p5A) for more context.

use ark_ff::Field;
use num_integer::binomial;

pub fn dimension_of_multivariate_polynomial<const N: usize, const D: usize>() -> usize {
    binomial(N + D, D)
}

/// Represents a multivariate polynomial of degree `D` in `N` variables.
pub struct MVPoly<F: Field, const N: usize, const D: usize> {
    pub coeff: Vec<F>,
}

impl<F: Field, const N: usize, const D: usize> MVPoly<F, N, D> {
    pub fn new() -> Self {
        MVPoly {
            coeff: vec![F::zero(); dimension_of_multivariate_polynomial::<N, D>()],
        }
    }
}

impl<F: Field, const N: usize, const D: usize> Default for MVPoly<F, N, D> {
    fn default() -> Self {
        MVPoly::new()
    }
}
