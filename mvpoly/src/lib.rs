//! This module contains the definition of the `MVPoly` trait, which is used to
//! represent multi-variate polynomials.
//!
//! Different representations are provided in the sub-modules:
//! - `monomials`: a representation based on monomials
//! - `prime`: a representation based on a mapping from variables to prime
//!    numbers. This representation is unmaintained for now. We leave it
//!    for interested users.
//!
//! "Expressions", as defined in the [kimchi] crate, can be converted into a
//! multi-variate polynomial using the `from_expr` method.

use ark_ff::PrimeField;
use kimchi::circuits::expr::{
    ConstantExpr, ConstantExprInner, ConstantTerm, Expr, ExprInner, Operations, Variable,
};
use rand::RngCore;
use std::collections::HashMap;

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
    /// For instance, in the case of [crate::prime], the output must be a prime
    /// number, starting at `2`. [crate::utils::PrimeNumberGenerator] can be
    /// used.
    /// For [crate::monomials], the output must be the index of the variable,
    /// starting from `0`.
    ///
    /// The parameter `offset_next_row` is an optional argument that is used to
    /// support the case where the "next row" is used. In this case, the type
    /// parameter `N` must include this offset (i.e. if 4 variables are in ued,
    /// N should be at least `8 = 2 * 4`).
    fn from_variable<Column: Into<usize>>(var: Variable<Column>, offset_next_row: Option<usize>) -> Self;

    fn from_constant<ChallengeTerm: Clone>(op: Operations<ConstantExprInner<F, ChallengeTerm>>) -> Self {
        use kimchi::circuits::expr::Operations::*;
        match op {
            Atom(op_const) => {
                match op_const {
                    ConstantExprInner::Challenge(_) => {
                        unimplemented!("Challenges are not supposed to be used in this context for now")
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
                    ConstantExprInner::Constant(ConstantTerm::Literal(c)) => Self::from(c),
                }
            }
            Add(c1, c2) => Self::from_constant(*c1) + Self::from_constant(*c2),
            Sub(c1, c2) => Self::from_constant(*c1) - Self::from_constant(*c2),
            Mul(c1, c2) => Self::from_constant(*c1) * Self::from_constant(*c2),
            Square(c) => Self::from_constant(*c.clone()) * Self::from_constant(*c),
            Double(c1) => Self::from_constant(*c1).double(),
            Pow(c, e) => {
                // FIXME: dummy implementation
                let p = Self::from_constant(*c);
                let mut result = p.clone();
                for _ in 0..e {
                    result = result.clone() * p.clone();
                }
                result
            }
            Cache(_c, _) => {
                unimplemented!("The method is supposed to be used for generic multivariate expressions, not tied to a specific use case like Kimchi with this constructor")
            }
            IfFeature(_c, _t, _f) => {
                unimplemented!("The method is supposed to be used for generic multivariate expressions, not tied to a specific use case like Kimchi with this constructor")
            }
        }
    }

    /// Build a value from an expression.
    /// This method aims to be used to be retro-compatible with what we call
    /// "the expression framework".
    /// In the near future, the "expression framework" should be moved also into
    /// this library.
    ///
    /// The mapping from variable to the user is left unspecified by this trait
    /// and is left to the implementation. The conversion of a variable into an
    /// index is done by the trait requirement `Into<usize>` on the column type.
    ///
    /// The parameter `offset_next_row` is an optional argument that is used to
    /// support the case where the "next row" is used. In this case, the type
    /// parameter `N` must include this offset (i.e. if 4 variables are in used,
    /// N should be at least `8 = 2 * 4`).
    fn from_expr<Column: Into<usize>, ChallengeTerm: Clone>(expr: Expr<ConstantExpr<F, ChallengeTerm>, Column>, offset_next_row: Option<usize>) -> Self {
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
                    ExprInner::Constant(c) => Self::from_constant(c),
                    ExprInner::Cell(var) => {
                        Self::from_variable::<Column>(var, offset_next_row)
                    }
                }
            }
            Add(e1, e2) => {
                let p1 = Self::from_expr::<Column, ChallengeTerm>(*e1, offset_next_row);
                let p2 = Self::from_expr::<Column, ChallengeTerm>(*e2, offset_next_row);
                p1 + p2
            }
            Sub(e1, e2) => {
                let p1 = Self::from_expr::<Column, ChallengeTerm>(*e1, offset_next_row);
                let p2 = Self::from_expr::<Column, ChallengeTerm>(*e2, offset_next_row);
                p1 - p2
            }
            Mul(e1, e2) => {
                let p1 = Self::from_expr::<Column, ChallengeTerm>(*e1, offset_next_row);
                let p2 = Self::from_expr::<Column, ChallengeTerm>(*e2, offset_next_row);
                p1 * p2
            }
            Double(p) => {
                let p = Self::from_expr::<Column, ChallengeTerm>(*p, offset_next_row);
                p.double()
            }
            Square(p) => {
                let p = Self::from_expr::<Column, ChallengeTerm>(*p, offset_next_row);
                p.clone() * p.clone()
            }
            Pow(c, e) => {
                // FIXME: dummy implementation
                let p = Self::from_expr::<Column, ChallengeTerm>(*c, offset_next_row);
                let mut result = p.clone();
                for _ in 0..e {
                    result = result.clone() * p.clone();
                }
                result
            }
            Cache(_c, _) => {
                unimplemented!("The method is supposed to be used for generic multivariate expressions, not tied to a specific use case like Kimchi with this constructor")
            }
            IfFeature(_c, _t, _f) => {
                unimplemented!("The method is supposed to be used for generic multivariate expressions, not tied to a specific use case like Kimchi with this constructor")
            }
        }
    }

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

    /// Compute the cross-terms of the given polynomial, scaled by the given
    /// scalar.
    ///
    /// More explicitly, given a polynomial `P(X1, ..., Xn)` and a scalar α, the
    /// method computes the cross-terms of the polynomial `Q(X1, ..., Xn, α)
    /// = α * P(X1, ..., Xn)`. For this reason, the method takes as input the
    /// two different scalars `scalar1` and `scalar2` as we are considering the
    /// scaling factor as a variable.
    ///
    /// This method is particularly useful when you need to compute a
    /// (possibly random) combinaison of polynomials `P1(X1, ..., Xn), ...,
    /// Pm(X1, ..., Xn)`, like when computing a quotient polynomial in the PlonK
    /// PIOP, as the result is the sum of individual "scaled" polynomials:
    /// ```text
    /// Q(X_1, ..., X_n, α_1, ..., α_m) =
    ///   α_1 P1(X_1, ..., X_n) +
    ///   ...
    ///   α_m Pm(X_1, ..., X_n) +
    /// ```
    ///
    /// The polynomial must not necessarily be homogeneous. For this reason, the
    /// values `u1` and `u2` represents the extra variable that is used to make
    /// the polynomial homogeneous.
    ///
    /// The homogeneous degree is supposed to be the one defined by the type of
    /// the polynomial `P`, i.e. `D`.
    ///
    /// The output is a map of `D` values that represents the cross-terms
    /// for each power of `r`.
    fn compute_cross_terms_scaled(
        &self,
        eval1: &[F; N],
        eval2: &[F; N],
        u1: F,
        u2: F,
        scalar1: F,
        scalar2: F,
    ) -> HashMap<usize, F>;

    /// Modify the monomial in the polynomial to the new value `coeff`.
    fn modify_monomial(&mut self, exponents: [usize; N], coeff: F);

    /// Return true if the multi-variate polynomial is multilinear, i.e. if each
    /// variable in each monomial is of maximum degree 1.
    fn is_multilinear(&self) -> bool;
}

/// Compute the cross terms of a list of polynomials. The polynomials are
/// linearly combined using the power of a combiner, often called `α`.
pub fn compute_combined_cross_terms<
    F: PrimeField,
    const N: usize,
    const D: usize,
    T: MVPoly<F, N, D>,
>(
    polys: Vec<T>,
    eval1: [F; N],
    eval2: [F; N],
    u1: F,
    u2: F,
    combiner1: F,
    combiner2: F,
) -> HashMap<usize, F> {
    // These should never happen as they should be random
    // It also makes the code cleaner as we do not need to handle 0^0
    assert!(combiner1 != F::zero());
    assert!(combiner2 != F::zero());
    assert!(u1 != F::zero());
    assert!(u2 != F::zero());
    polys
        .into_iter()
        .enumerate()
        .fold(HashMap::new(), |mut acc, (i, poly)| {
            let scalar1 = combiner1.pow([i as u64]);
            let scalar2 = combiner2.pow([i as u64]);
            let res = poly.compute_cross_terms_scaled(&eval1, &eval2, u1, u2, scalar1, scalar2);
            res.iter().for_each(|(p, r)| {
                acc.entry(*p).and_modify(|e| *e += r).or_insert(*r);
            });
            acc
        })
}
