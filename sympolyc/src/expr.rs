//! Multivariate polynomial
//! See [these notes](https://hackmd.io/@dannywillems/SyHar7p5A) for more context.

use std::ops::Add;

use ark_ff::Field;
use num_integer::binomial;

pub fn dimension_of_multivariate_polynomial<const N: usize, const D: usize>() -> usize {
    binomial(N + D, D)
}

/// Represents a multivariate polynomial of degree `D` in `N` variables.
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

    pub fn number_of_variables(&self) -> usize {
        N
    }

    pub fn maximum_degree(&self) -> usize {
        D
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
