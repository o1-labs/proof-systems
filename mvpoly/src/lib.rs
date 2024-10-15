//! This module contains the definition of the `MVPoly` trait, which is used to
//! represent multi-variate polynomials.
//!
//! Different representations are provided in the sub-modules:
//! - `monomials`: a representation based on monomials
//! - `prime`: a representation based on a mapping from variables to prime
//! numbers. This representation is unmaintained for now. We leave it
//! for interested users.
//!
//! "Expressions", as defined in the [kimchi] crate, can be converted into a
//! multi-variate polynomial using the `from_expr` method.

use std::collections::HashMap;

use ark_ff::PrimeField;
use kimchi::circuits::expr::{ConstantExpr, Expr};
use rand::RngCore;

pub mod monomials;
pub mod pbt;
pub mod prime;
pub mod utils;

/// Generic trait to represent a multi-variate polynomial
pub trait MVPoly<F: PrimeField, const N: usize, const D: usize>:
    // Addition
    std::ops::Add<Self, Output = Self>
    + for<'a> std::ops::Add<&'a Self, Output = Self>
    // Mul
    + std::ops::Mul<Self, Output = Self>
    // Negation
    + std::ops::Neg<Output = Self>
    // Sub
    + std::ops::Sub<Self, Output = Self>
    + for<'a> std::ops::Sub<&'a Self, Output = Self>
    + ark_ff::One
    + ark_ff::Zero
    + std::fmt::Debug
    + Clone
    // Comparison operators
    + PartialEq
    + Eq
    // Useful conversions
    + From<F>
    + Sized
{
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
    unsafe fn random<RNG: RngCore>(rng: &mut RNG, max_degree: Option<usize>) -> Self;

    fn double(&self) -> Self;

    fn is_constant(&self) -> bool;

    fn mul_by_scalar(&self, scalar: F) -> Self;

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
    unsafe fn degree(&self) -> usize;

    /// Evaluate the polynomial at the vector point `x`.
    ///
    /// This is a dummy implementation. A cache can be used for the monomials to
    /// speed up the computation.
    fn eval(&self, x: &[F; N]) -> F;


    /// Build the univariate polynomial `x_i` from the variable `i`.
    /// The conversion into the type `usize` is unspecified by this trait. It
    /// is left to the trait implementation.
    /// For instance, in the case of [mvpoly::prime], the output must be a prime
    /// number, starting at `2`. [mvpoly::utils::PrimeNumberGenerator] can be
    /// used.
    /// For [mvpoly::monomials], the output must be the index of the variable,
    /// starting from `0`.
    fn from_variable<Column: Into<usize>>(var: Column) -> Self;

    /// Build a value from an expression.
    /// This method aims to be used to be retro-compatible with what we call
    /// "the expression framework".
    /// In the near future, the "expression framework" should be moved also into
    /// this library.
    fn from_expr<Column: Into<usize>, ChallengeTerm: Clone>(expr: Expr<ConstantExpr<F, ChallengeTerm>, Column>) -> Self;

    /// Returns true if the polynomial is homogeneous (of degree `D`).
    /// As a reminder, a polynomial is homogeneous if all its monomials have the
    /// same degree.
    fn is_homogeneous(&self) -> bool;

    /// Evaluate the polynomial at the vector point `x` and the extra variable
    /// `u` using its homogeneous form of degree D.
    fn homogeneous_eval(&self, x: &[F; N], u: F) -> F;

    /// Add the monomial `coeff * x_1^{e_1} * ... * x_N^{e_N}` to the
    /// polynomial, where `e_i` are the values given by the array `exponents`.
    ///
    /// For instance, to add the monomial `3 * x_1^2 * x_2^3` to the polynomial,
    /// one would call `add_monomial([2, 3], 3)`.
    fn add_monomial(&mut self, exponents: [usize; N], coeff: F);

    /// Compute the cross-terms as described in [Behind Nova: cross-terms
    /// computation for high degree
    /// gates](https://hackmd.io/@dannywillems/Syo5MBq90)
    ///
    /// The polynomial must not necessarily be homogeneous. For this reason, the
    /// values `u1` and `u2` represents the extra variable that is used to make
    /// the polynomial homogeneous.
    ///
    /// The homogeneous degree is supposed to be the one defined by the type of
    /// the polynomial, i.e. `D`.
    ///
    /// The output is a map of `D - 1` values that represents the cross-terms
    /// for each power of `r`.
    fn compute_cross_terms(
        &self,
        eval1: &[F; N],
        eval2: &[F; N],
        u1: F,
        u2: F,
    ) -> HashMap<usize, F>;

    /// Modify the monomial in the polynomial to the new value `coeff`.
    fn modify_monomial(&mut self, exponents: [usize; N], coeff: F);

    /// Return true if the multi-variate polynomial is multilinear, i.e. if each
    /// variable in each monomial is of maximum degree 1.
    fn is_multilinear(&self) -> bool;
}
