//! Implement a library to represent expressions/multivariate polynomials that
//! can be used with folding schemes like
//! [Nova](https://eprint.iacr.org/2021/370).
//!
//! We do enforce expressions to be degree `2` maximum to apply our folding
//! scheme.
//!
//! Before folding, we do suppose that each expression has been reduced to
//! degree `2` using [crate::quadraticization].
//!
//! The library introduces different types of expressions:
//! - [FoldingCompatibleExpr]: an expression that can be used with folding. It
//!   aims to be an intermediate representation from
//!   [kimchi::circuits::expr::Expr]. It can be printed in a human-readable way
//!   using the trait [ToString].
//! - [FoldingExp]: an internal representation of a folded expression.
//! - [IntegratedFoldingExpr]: a simplified expression with all terms separated
//!
//! When using the library, the user should:
//! - Convert an expression from [kimchi::circuits::expr::Expr] into a
//!   [FoldingCompatibleExpr] using the trait [From].
//! - Convert a list of [FoldingCompatibleExpr] into a [IntegratedFoldingExpr]
//!   using the function [folding_expression].
//!
//! The user can also choose to build a structure [crate::FoldingScheme] from a
//! list of [FoldingCompatibleExpr].
//!
//! As a reminder, after we reduce to degree 2, the multivariate polynomial
//! `P(X_{1}, ..., X_{n})` describing the NP relation will be
//! "relaxed" in another polynomial of the form `P_relaxed(X_{1}, ..., X_{n}, u)`.
//! First, we decompose the polynomial `P` in its monomials of degree `0`, `1` and `2`:
//! ```text
//! P(X_{1}, ..., X_{n}) = ∑_{i} f_{i, 0}(X_{1}, ..., X_{n}) +
//!                        ∑_{i} f_{i, 1}(X_{1}, ..., X_{n}) +
//!                        ∑_{i} f_{i, 2}(X_{1}, ..., X_{n})
//! ```
//! where `f_{i, 0}` is a monomial of degree `0`, `f_{i, 1}` is a monomial of degree
//! `1` and `f_{i, 2}` is a monomial of degree `2`.
//! For instance, for the polynomial `P(X_{1}, X_{2}, X_{3}) = X_{1} * X_{2} +
//! (1 - X_{3})`, we have:
//! ```text
//! f_{0, 0}(X_{1}, X_{2}, X_{3}) = 1
//! f_{0, 1}(X_{1}, X_{2}, X_{3}) = -X_{3}
//! f_{0, 2}(X_{1}, X_{2}, X_{3}) = X_{1} * X_{2}
//! ```
//! Then, we can relax the polynomial `P` in `P_relaxed` by adding a new
//! variable `u` in the following way:
//! - For the monomials `f_{i, 0}`, i.e. the monomials of degree `0`, we add
//!   `u^2` to the expression.
//! - For the monomials `f_{i, 1}`, we add `u` to the expression.
//! - For the monomials `f_{i, 2}`, we keep the expression as is.
//!
//! For the polynomial `P(X_{1}, X_{2}, X_{3}) = X_{1} * X_{2} + (1 - X_{3})`, we have:
//! ```text
//! P_relaxed(X_{1}, X_{2}, X_{3}, u) = X_{1} * X_{2} + u (u - X_{3})
//! ```
//!
//! From the relaxed form of the polynomial, we can "fold" multiple instances of
//! the NP relation by randomising it into a single instance by adding an error
//! term `E`.
//! For instance, for the polynomial `P_relaxed(X_{1}, X_{2}, X_{3}, u) = X_{1} *
//! X_{2} + u (u - X_{3})`,
//! for two instances `(X_{1}, X_{2}, X_{3}, u)` and `(X_{1}', X_{2}', X_{3}',
//! u')`, we can fold them into a single instance by coining a random value `r`:
//! ```text
//! X''_{1} = X_{1} + r X_{1}'
//! X''_{2} = X_{2} + r X_{2}'
//! X''_{3} = X_{3} + r X_{3}'
//! u'' = u + r u'
//! ```
//! Computing the polynomial `P_relaxed(X''_{1}, X''_{2}, X''_{3}, u'')` will
//! give:
//! ```text
//!   (X_{1} + r X'_{1}) (X_{2} + r X'_{2}) \
//! + (u + r u') [(u + r u') - (X_{3} + r X'_{3})]
//! ```
//! which can be simplified into:
//! ```text
//!   P_relaxed(X_{1}, X_{2}, X_{3}, u) + P_relaxed(r X_{1}', r X_{2}', r X_{3}', r u')
//! + r [u (u' - X_{3}) + u' (u - X_{3})] + r [X_{1} X_{2}'   +   X_{2} X_{1}']
//!   \---------------------------------/   \----------------------------------/
//!  cross terms of monomials of degree 1   cross terms of monomials of degree 2
//!              and degree 0
//! ```
//! The error term `T` (or "cross term") is the last term of the expression,
//! multiplied by `r`.
//! More generally, the error term is the sum of all monomials introduced by
//! the "cross terms" of the instances. For example, if there is a monomial of
//! degree 2 like `X_{1} * X_{2}`, it introduces the cross terms
//! `r X_{1} X_{2}' + r X_{2} X_{1}'`. For a monomial of degree 1, for example
//! `u X_{1}`, it introduces the cross terms `r u X_{1}' + r u' X_{1}`.
//!
//! Note that:
//! ```text
//!       P_relaxed(r X_{1}', r X_{2}', r X_{3}', r u')
//! = r^2 P_relaxed(X_{1}',   X_{2}',   X_{3}',   u')
//! ```
//! and `P_relaxed` is of degree `2`. More
//! precisely, `P_relaxed` is homogeneous. And that is the main idea of folding:
//! the "relaxation" of a polynomial means we make it homogeneous for a certain
//! degree `d` by introducing the new variable `u`, and introduce the concept of
//! "error terms" that will englobe the "cross-terms". The prover takes care of
//! computing the cross-terms and commit to them.
//!
//! While folding, we aggregate the error terms of all instances into a single
//! error term, E.
//! In our example, if we have a folded instance with the non-zero
//! error terms `E_{1}` and `E_{2}`, we have:
//! ```text
//! E = E_{1} + r T + E_{2}
//! ```
//!
//! ## Aggregating constraints
//!
//! The library also provides a way to fold NP relations described by a list of
//! multi-variate polynomials, like we usually have in a zkSNARK circuit.
//!
//! In PlonK, we aggregate all the polynomials into a single polynomial by
//! coining a random value `α`. For instance, if we have two polynomials `P` and
//! `Q` describing our computation in a zkSNARK circuit, we usually use the
//! randomized polynomial `P + α Q` (used to build the quotient polynomial in
//! PlonK).
//!
//! More generally, if for each row, our computation is constrained by the polynomial
//! list `[P_{1}, P_{2}, ..., P_{n}]`, we can aggregate them into a single
//! polynomial `P_{agg} = ∑_{i} α^{i} P_{i}`. Multiplying by the α terms
//! consequently increases the overall degree of the expression.
//!
//! In particular, when we reduce a polynomial to degree 2, we have this case
//! where the circuit is described by a list of polynomials and we aggregate
//! them into a single polynomial.
//!
//! For instance, if we have two polynomials `P(X_{1}, X_{2}, X_{3})` and
//! `Q(X_{1}, X_{2}, X_{3})` such that:
//! ```text
//! P(X_{1}, X_{2}, X_{3}) = X_{1} * X_{2} + (1 - X_{3})
//! Q(X_{1}, X_{2}, X_{3}) = X_{1} + X_{2}
//! ```
//!
//! The relaxed form of the polynomials are:
//! ```text
//! P_relaxed(X_{1}, X_{2}, X_{3}, u) = X_{1} * X_{2} + u (u - X_{3})
//! Q_relaxed(X_{1}, X_{2}, X_{3}, u) = u X_{1} + u X_{2}
//! ```
//!
//! We start by coining `α_{1}` and `α_{2}` and we compute the polynomial
//! `P'(X_{1}, X_{2}, X_{3}, u, α_{1})` and `Q'(X_{1}, X_{2}, X_{3}, α_{2})` such that:
//! ```text
//! P'(X_{1}, X_{2}, X_{3}, u, α_{1}) = α_{1} P_relaxed(X_{1}, X_{2}, X_{3}, u)
//!                                   = α_{1} (X_{1} * X_{2} + u (u - X_{3}))
//!                                   = α_{1} X_{1} * X_{2} + α_{1} u^2 - α_{1} u X_{3}
//! Q'(X_{1}, X_{2}, X_{3}, u, α_{2}) = α_{2} Q_relaxed(X_{1}, X_{2}, X_{3}, u)
//!                                   = α_{2} (u X_{1} + u X_{2})
//!                                   = α_{2} u X_{1} + α_{2} u X_{2}
//! ```
//! and we want to fold the multivariate polynomial S defined over six
//! variables:
//! ```text
//!   S(X_{1}, X_{2}, X_{3}, u, α_{1}, α_{2})
//! = P'(X_{1}, X_{2}, X_{3}, u, α_{1}) + Q'(X_{1}, X_{2}, X_{3}, u, α_{2})`.
//! = α_{1} X_{1} X_{2} +
//!   α_{1} u^2 -
//!   α_{1} u X_{3} +
//!   α_{2} u X_{1} +
//!   α_{2} u X_{2}
//! ```
//!
//! Note that we end up with everything of the same degree, which is `3` in this
//! case. The variables `α_{1}` and `α_{2}` increase the degree of the
//! homogeneous expressions by one.
//!
//! For two given instances `(X_{1}, X_{2}, X_{3}, u, α_{1}, α_{2})` and
//! `(X_{1}', X_{2}', X_{3}', u', α_{1}', α_{2}')`, we coin a random value `r` and we compute:
//! ```text
//! X''_{1} = X_{1} + r X'_{1}
//! X''_{2} = X_{2} + r X'_{2}
//! X''_{3} = X_{3} + r X'_{3}
//! u'' = u + r u'
//! α''_{1} = α_{1} + r α'_{1}
//! α''_{2} = α_{2} + r α'_{2}
//! ```
//!
//! From there, we compute the evaluations of the polynomial S at the point
//! `S(X''_{1}, X''_{2}, X''_{3}, u'', α''_{1}, α''_{2})`, which gives:
//! ```text
//!   S(X_{1}, X_{2}, X_{3}, u, α_{1}, α_{2})
//! + S(r X'_{1}, r X'_{2}, r X'_{3}, r u', r α'_{1}, r α'_{2})
//! + r T_{0}
//! + r^2 T_{1}
//! ```
//! where `T_{0}` (respectively `T_{1}`) are cross terms that are multiplied by
//! `r` (respectively `r^2`). More precisely, for `T_{0}` we have:
//! ```text
//! T_{0} = a_{1} X_{1} X'{2} +
//!         X_{2} (α_{1} X'_{1} + α'_{1} X_{1}) +
//!         // we repeat for a_{1} u^{2}, ... as described below
//! ```
//! We must see each monomial as a polynomial P(X, Y, Z) of degree 3, and the
//! cross-term for each monomial will be, for (X', Y', Z') and (X, Y, Z):
//! ```text
//! X Y Z' + Z (X Y' + X' Y)
//! ```
//!
//! As for the degree`2` case described before, we notice that the polynomial S
//! is homogeneous of degree 3, i.e.
//! ```text
//!       S(r X'_{1}, r X'_{2}, r X'_{3}, r u', r α'_{1}, r α'_{2})
//! = r^3 S(X'_{1},   X'_{2},   X'_{3},   u',   α'_{1},   α'_{2})
//! ```
//!
//! ## Fiat-Shamir challenges, interactive protocols and lookup arguments
//!
//! Until now, we have described a way to fold multi-variate polynomials, which
//! is mostly a generalization of [Nova](https://eprint.iacr.org/2021/370) for
//! any multi-variate polynomial.
//! However, we did not describe how it can be used to describe and fold
//! interactive protocols based on polynomials, like PlonK. We do suppose the
//! interactive protocol can be made non-interactive by using the Fiat-Shamir
//! transformation.
//!
//! To fold interactive protocols, our folding scheme must also support
//! Fiat-Shamir challenges. This implementation handles this by representing
//! challenges as new variables in the polynomial describing the NP relation.
//! The challenges are then aggregated in the same way as the other variables.
//!
//! For instance, let's consider the additive
//! lookup/logup argument. For a detailed description of the protocol, see [the
//! online
//! documentation](https://o1-labs.github.io/proof-systems/rustdoc/kimchi_msm/logup/index.html).
//! We will suppose we have only one table `T` and Alice wants to prove to Bob
//! that she knows that all evaluations of `f(X)` is in `t(X)`. The additive
//! lookup argument is described by the polynomial equation:
//! ```text
//! β + f(x) = m(x) (β + t(x))
//! ```
//! where β is the challenge, `f(x)` is the polynomial whose evaluations describe
//! the value Alice wants to prove to Bob that is in the table, `m(x)` is
//! the polynomial describing the multiplicities, and `t(x)` is the
//! polynomial describing the (fixed) table.
//!
//! The equation can be described by the multi-variate polynomial `LOGUP`:
//! ```text
//! LOGUP(β, F, M, T) = β + F - M (β + T)
//! ```
//!
//! The relaxed/homogeneous version of the polynomial LOGUP is:
//! ```text
//! LOGUP_relaxed(β, F, M, T, u) = u β + u F - M (β + T)
//! ```
//!
//! Folding this polynomial means that we will coin a random value `r`, and we compute:
//! ```text
//! β'' = β + r β'
//! F'' = F + r F'
//! M'' = M + r M'
//! T'' = T + r T'
//! u'' = u + r u'
//! ```
//!
//! ## Supporting polynomial commitment blinders
//!
//! The library also supports polynomial commitment blinders. The blinding
//! factors are represented as new variables in the polynomial describing the NP
//! relation. The blinding factors are then aggregated in the same way as the
//! other variables.
//! We want to support blinders in the polynomial commitment scheme to avoid
//! committing to the zero zero polynomial. Using a blinder, we can always
//! suppose that our elliptic curves points are not the point at infinity.
//! The library handles the blinding factors as variables in each instance.
//!
//! When doing the final proof, the blinder factor that will need to be used is
//! the one from the final relaxed instance.

use crate::{
    columns::ExtendedFoldingColumn,
    quadraticization::{quadraticize, ExtendedWitnessGenerator, Quadraticized},
    FoldingConfig, ScalarField,
};
use ark_ec::AffineRepr;
use ark_ff::{One, Zero};
use core::{
    fmt,
    fmt::{Display, Formatter},
};
use derivative::Derivative;
use itertools::Itertools;
use kimchi::circuits::{
    berkeley_columns::BerkeleyChallengeTerm,
    expr::{ConstantExprInner, ConstantTerm, ExprInner, Operations, Variable},
    gate::CurrOrNext,
};

/// Describe the degree of a constraint.
/// As described in the [top level documentation](super::expressions), we only
/// support constraints with degree up to `2`
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Degree {
    Zero,
    One,
    Two,
}

impl core::ops::Add for Degree {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        use Degree::*;
        match (self, rhs) {
            (_, Two) | (Two, _) => Two,
            (_, One) | (One, _) => One,
            (Zero, Zero) => Zero,
        }
    }
}

impl core::ops::Mul for &Degree {
    type Output = Degree;

    fn mul(self, rhs: Self) -> Self::Output {
        use Degree::*;
        match (self, rhs) {
            (Zero, other) | (other, Zero) => *other,
            (One, One) => Two,
            _ => panic!("The folding library does support only expressions of degree `2` maximum"),
        }
    }
}

pub trait FoldingColumnTrait: Copy + Clone {
    fn is_witness(&self) -> bool;

    /// Return the degree of the column
    /// - `0` if the column is a constant
    /// - `1` if the column will take part of the randomisation (see [top level
    ///   documentation](super::expressions)
    fn degree(&self) -> Degree {
        match self.is_witness() {
            true => Degree::One,
            false => Degree::Zero,
        }
    }
}

/// Extra expressions that can be created by folding
#[derive(Derivative)]
#[derivative(
    Clone(bound = "C: FoldingConfig"),
    Debug(bound = "C: FoldingConfig"),
    PartialEq(bound = "C: FoldingConfig")
)]
pub enum ExpExtension<C: FoldingConfig> {
    /// The variable `u` used to make the polynomial homogeneous
    U,
    /// The error term
    Error,
    /// Additional columns created by quadraticization
    ExtendedWitness(usize),
    /// The random values `α_{i}` used to aggregate constraints
    Alpha(usize),
    /// Represent a dynamic selector, in the case of using decomposable folding
    Selector(C::Selector),
}

/// Components to be used to convert multivariate polynomials into "compatible"
/// multivariate polynomials that will be translated to folding expressions.
#[derive(Derivative)]
#[derivative(
    Clone(bound = "C: FoldingConfig"),
    PartialEq(bound = "C: FoldingConfig"),
    Debug(bound = "C: FoldingConfig")
)]
pub enum FoldingCompatibleExprInner<C: FoldingConfig> {
    Constant(<C::Curve as AffineRepr>::ScalarField),
    Challenge(C::Challenge),
    Cell(Variable<C::Column>),
    /// extra nodes created by folding, should not be passed to folding
    Extensions(ExpExtension<C>),
}

/// Compatible folding expressions that can be used with folding schemes.
/// An expression from [kimchi::circuits::expr::Expr] can be converted into a
/// [FoldingCompatibleExpr] using the trait [From].
/// From there, an expression of type [IntegratedFoldingExpr] can be created
/// using the function [folding_expression].
#[derive(Derivative)]
#[derivative(
    Clone(bound = "C: FoldingConfig"),
    PartialEq(bound = "C: FoldingConfig"),
    Debug(bound = "C: FoldingConfig")
)]
pub enum FoldingCompatibleExpr<C: FoldingConfig> {
    Atom(FoldingCompatibleExprInner<C>),
    Pow(Box<Self>, u64),
    Add(Box<Self>, Box<Self>),
    Sub(Box<Self>, Box<Self>),
    Mul(Box<Self>, Box<Self>),
    Double(Box<Self>),
    Square(Box<Self>),
}

impl<C: FoldingConfig> core::ops::Add for FoldingCompatibleExpr<C> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        Self::Add(Box::new(self), Box::new(rhs))
    }
}

impl<C: FoldingConfig> core::ops::Sub for FoldingCompatibleExpr<C> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self {
        Self::Sub(Box::new(self), Box::new(rhs))
    }
}

impl<C: FoldingConfig> core::ops::Mul for FoldingCompatibleExpr<C> {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self {
        Self::Mul(Box::new(self), Box::new(rhs))
    }
}

/// Implement a human-readable version of a folding compatible expression.
impl<C: FoldingConfig> Display for FoldingCompatibleExpr<C> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            FoldingCompatibleExpr::Atom(c) => match c {
                FoldingCompatibleExprInner::Constant(c) => {
                    if c.is_zero() {
                        write!(f, "0")
                    } else {
                        write!(f, "{}", c)
                    }
                }
                FoldingCompatibleExprInner::Challenge(c) => {
                    write!(f, "{:?}", c)
                }
                FoldingCompatibleExprInner::Cell(cell) => {
                    let Variable { col, row } = cell;
                    let next = match row {
                        CurrOrNext::Curr => "",
                        CurrOrNext::Next => " * ω",
                    };
                    write!(f, "Col({:?}){}", col, next)
                }
                FoldingCompatibleExprInner::Extensions(e) => match e {
                    ExpExtension::U => write!(f, "U"),
                    ExpExtension::Error => write!(f, "E"),
                    ExpExtension::ExtendedWitness(i) => {
                        write!(f, "ExWit({})", i)
                    }
                    ExpExtension::Alpha(i) => write!(f, "α_{i}"),
                    ExpExtension::Selector(s) => write!(f, "Selec({:?})", s),
                },
            },
            FoldingCompatibleExpr::Double(e) => {
                write!(f, "2 {}", e)
            }
            FoldingCompatibleExpr::Square(e) => {
                write!(f, "{} ^ 2", e)
            }
            FoldingCompatibleExpr::Add(e1, e2) => {
                write!(f, "{} + {}", e1, e2)
            }
            FoldingCompatibleExpr::Sub(e1, e2) => {
                write!(f, "{} - {}", e1, e2)
            }
            FoldingCompatibleExpr::Mul(e1, e2) => {
                write!(f, "({}) ({})", e1, e2)
            }
            FoldingCompatibleExpr::Pow(_, _) => todo!(),
        }
    }
}

/// Internal expression used for folding.
/// A "folding" expression is a multivariate polynomial like defined in
/// [kimchi::circuits::expr] with the following differences.
/// - No constructors related to zero-knowledge or lagrange basis (i.e. no
///   constructors related to the PIOP)
/// - The variables includes a set of columns that describes the initial circuit
///   shape, with additional columns strictly related to the folding scheme (error
///   term, etc).
// TODO: renamed in "RelaxedExpression"?
#[derive(Derivative)]
#[derivative(
    Hash(bound = "C:FoldingConfig"),
    Debug(bound = "C:FoldingConfig"),
    Clone(bound = "C:FoldingConfig"),
    PartialEq(bound = "C:FoldingConfig"),
    Eq(bound = "C:FoldingConfig")
)]
pub enum FoldingExp<C: FoldingConfig> {
    Atom(ExtendedFoldingColumn<C>),
    Pow(Box<Self>, u64),
    Add(Box<Self>, Box<Self>),
    Mul(Box<Self>, Box<Self>),
    Sub(Box<Self>, Box<Self>),
    Double(Box<Self>),
    Square(Box<Self>),
}

impl<C: FoldingConfig> core::ops::Add for FoldingExp<C> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        Self::Add(Box::new(self), Box::new(rhs))
    }
}

impl<C: FoldingConfig> core::ops::Sub for FoldingExp<C> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self {
        Self::Sub(Box::new(self), Box::new(rhs))
    }
}

impl<C: FoldingConfig> core::ops::Mul for FoldingExp<C> {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self {
        Self::Mul(Box::new(self), Box::new(rhs))
    }
}

impl<C: FoldingConfig> FoldingExp<C> {
    pub fn double(self) -> Self {
        Self::Double(Box::new(self))
    }
}

/// Converts an expression "compatible" with folding into a folded expression.
// TODO: use "into"?
// FIXME: add independent tests
// FIXME: test independently the behavior of pow_to_mul, and explain only why 8
// maximum
impl<C: FoldingConfig> FoldingCompatibleExpr<C> {
    pub fn simplify(self) -> FoldingExp<C> {
        use FoldingExp::*;
        match self {
            FoldingCompatibleExpr::Atom(atom) => match atom {
                FoldingCompatibleExprInner::Constant(c) => Atom(ExtendedFoldingColumn::Constant(c)),
                FoldingCompatibleExprInner::Challenge(c) => {
                    Atom(ExtendedFoldingColumn::Challenge(c))
                }
                FoldingCompatibleExprInner::Cell(col) => Atom(ExtendedFoldingColumn::Inner(col)),
                FoldingCompatibleExprInner::Extensions(ext) => {
                    match ext {
                        // TODO: this shouldn't be allowed, but is needed for now to add
                        // decomposable folding without many changes, it should be
                        // refactored at some point in the future
                        ExpExtension::Selector(s) => Atom(ExtendedFoldingColumn::Selector(s)),
                        _ => {
                            panic!("this should only be created by folding itself")
                        }
                    }
                }
            },
            FoldingCompatibleExpr::Double(exp) => Double(Box::new((*exp).simplify())),
            FoldingCompatibleExpr::Square(exp) => Square(Box::new((*exp).simplify())),
            FoldingCompatibleExpr::Add(e1, e2) => {
                let e1 = Box::new(e1.simplify());
                let e2 = Box::new(e2.simplify());
                Add(e1, e2)
            }
            FoldingCompatibleExpr::Sub(e1, e2) => {
                let e1 = Box::new(e1.simplify());
                let e2 = Box::new(e2.simplify());
                Sub(e1, e2)
            }
            FoldingCompatibleExpr::Mul(e1, e2) => {
                let e1 = Box::new(e1.simplify());
                let e2 = Box::new(e2.simplify());
                Mul(e1, e2)
            }
            FoldingCompatibleExpr::Pow(e, p) => Self::pow_to_mul(e.simplify(), p),
        }
    }

    fn pow_to_mul(exp: FoldingExp<C>, p: u64) -> FoldingExp<C>
    where
        C::Column: Clone,
        C::Challenge: Clone,
    {
        use FoldingExp::*;
        let e = Box::new(exp);
        let e_2 = Box::new(Square(e.clone()));
        match p {
            2 => *e_2,
            3 => Mul(e, e_2),
            4..=8 => {
                let e_4 = Box::new(Square(e_2.clone()));
                match p {
                    4 => *e_4,
                    5 => Mul(e, e_4),
                    6 => Mul(e_2, e_4),
                    7 => Mul(e, Box::new(Mul(e_2, e_4))),
                    8 => Square(e_4),
                    _ => unreachable!(),
                }
            }
            _ => panic!("unsupported"),
        }
    }

    /// Maps variable (column index) in expression using the `mapper`
    /// function. Can be used to modify (remap) the indexing of
    /// columns after the expression is built.
    pub fn map_variable(
        self,
        mapper: &(dyn Fn(Variable<C::Column>) -> Variable<C::Column>),
    ) -> FoldingCompatibleExpr<C> {
        use FoldingCompatibleExpr::*;
        match self {
            FoldingCompatibleExpr::Atom(atom) => match atom {
                FoldingCompatibleExprInner::Cell(col) => {
                    Atom(FoldingCompatibleExprInner::Cell((mapper)(col)))
                }
                atom => Atom(atom),
            },
            FoldingCompatibleExpr::Double(exp) => Double(Box::new(exp.map_variable(mapper))),
            FoldingCompatibleExpr::Square(exp) => Square(Box::new(exp.map_variable(mapper))),
            FoldingCompatibleExpr::Add(e1, e2) => {
                let e1 = Box::new(e1.map_variable(mapper));
                let e2 = Box::new(e2.map_variable(mapper));
                Add(e1, e2)
            }
            FoldingCompatibleExpr::Sub(e1, e2) => {
                let e1 = Box::new(e1.map_variable(mapper));
                let e2 = Box::new(e2.map_variable(mapper));
                Sub(e1, e2)
            }
            FoldingCompatibleExpr::Mul(e1, e2) => {
                let e1 = Box::new(e1.map_variable(mapper));
                let e2 = Box::new(e2.map_variable(mapper));
                Mul(e1, e2)
            }
            FoldingCompatibleExpr::Pow(e, p) => Pow(Box::new(e.map_variable(mapper)), p),
        }
    }

    /// Map all quad columns into regular witness columns.
    pub fn flatten_quad_columns(
        self,
        mapper: &(dyn Fn(usize) -> Variable<C::Column>),
    ) -> FoldingCompatibleExpr<C> {
        use FoldingCompatibleExpr::*;
        match self {
            FoldingCompatibleExpr::Atom(atom) => match atom {
                FoldingCompatibleExprInner::Extensions(ExpExtension::ExtendedWitness(i)) => {
                    Atom(FoldingCompatibleExprInner::Cell((mapper)(i)))
                }
                atom => Atom(atom),
            },
            FoldingCompatibleExpr::Double(exp) => {
                Double(Box::new(exp.flatten_quad_columns(mapper)))
            }
            FoldingCompatibleExpr::Square(exp) => {
                Square(Box::new(exp.flatten_quad_columns(mapper)))
            }
            FoldingCompatibleExpr::Add(e1, e2) => {
                let e1 = Box::new(e1.flatten_quad_columns(mapper));
                let e2 = Box::new(e2.flatten_quad_columns(mapper));
                Add(e1, e2)
            }
            FoldingCompatibleExpr::Sub(e1, e2) => {
                let e1 = Box::new(e1.flatten_quad_columns(mapper));
                let e2 = Box::new(e2.flatten_quad_columns(mapper));
                Sub(e1, e2)
            }
            FoldingCompatibleExpr::Mul(e1, e2) => {
                let e1 = Box::new(e1.flatten_quad_columns(mapper));
                let e2 = Box::new(e2.flatten_quad_columns(mapper));
                Mul(e1, e2)
            }
            FoldingCompatibleExpr::Pow(e, p) => Pow(Box::new(e.flatten_quad_columns(mapper)), p),
        }
    }
}

impl<C: FoldingConfig> FoldingExp<C> {
    /// Compute the degree of a folding expression.
    /// Only constants are of degree `0`, the rest is of degree `1`.
    /// An atom of degree `1` means that the atom is going to be randomised as
    /// described in the [top level documentation](super::expressions).
    pub(super) fn folding_degree(&self) -> Degree {
        use Degree::*;
        match self {
            FoldingExp::Atom(ex_col) => match ex_col {
                ExtendedFoldingColumn::Inner(col) => col.col.degree(),
                ExtendedFoldingColumn::WitnessExtended(_) => One,
                ExtendedFoldingColumn::Error => One,
                ExtendedFoldingColumn::Constant(_) => Zero,
                ExtendedFoldingColumn::Challenge(_) => One,
                ExtendedFoldingColumn::Alpha(_) => One,
                ExtendedFoldingColumn::Selector(_) => One,
            },
            FoldingExp::Double(e) => e.folding_degree(),
            FoldingExp::Square(e) => &e.folding_degree() * &e.folding_degree(),
            FoldingExp::Mul(e1, e2) => &e1.folding_degree() * &e2.folding_degree(),
            FoldingExp::Add(e1, e2) | FoldingExp::Sub(e1, e2) => {
                e1.folding_degree() + e2.folding_degree()
            }
            FoldingExp::Pow(_, 0) => Zero,
            FoldingExp::Pow(e, 1) => e.folding_degree(),
            FoldingExp::Pow(e, i) => {
                let degree = e.folding_degree();
                let mut acc = degree;
                for _ in 1..*i {
                    acc = &acc * &degree;
                }
                acc
            }
        }
    }

    /// Convert a folding expression into a compatible one.
    fn into_compatible(self) -> FoldingCompatibleExpr<C> {
        use FoldingCompatibleExpr::*;
        use FoldingCompatibleExprInner::*;
        match self {
            FoldingExp::Atom(c) => match c {
                ExtendedFoldingColumn::Inner(col) => Atom(Cell(col)),
                ExtendedFoldingColumn::WitnessExtended(i) => {
                    Atom(Extensions(ExpExtension::ExtendedWitness(i)))
                }
                ExtendedFoldingColumn::Error => Atom(Extensions(ExpExtension::Error)),
                ExtendedFoldingColumn::Constant(c) => Atom(Constant(c)),
                ExtendedFoldingColumn::Challenge(c) => Atom(Challenge(c)),
                ExtendedFoldingColumn::Alpha(i) => Atom(Extensions(ExpExtension::Alpha(i))),
                ExtendedFoldingColumn::Selector(s) => Atom(Extensions(ExpExtension::Selector(s))),
            },
            FoldingExp::Double(exp) => Double(Box::new(exp.into_compatible())),
            FoldingExp::Square(exp) => Square(Box::new(exp.into_compatible())),
            FoldingExp::Add(e1, e2) => {
                let e1 = Box::new(e1.into_compatible());
                let e2 = Box::new(e2.into_compatible());
                Add(e1, e2)
            }
            FoldingExp::Sub(e1, e2) => {
                let e1 = Box::new(e1.into_compatible());
                let e2 = Box::new(e2.into_compatible());
                Sub(e1, e2)
            }
            FoldingExp::Mul(e1, e2) => {
                let e1 = Box::new(e1.into_compatible());
                let e2 = Box::new(e2.into_compatible());
                Mul(e1, e2)
            }
            // TODO: Replace with `Pow`
            FoldingExp::Pow(_, 0) => Atom(Constant(<C::Curve as AffineRepr>::ScalarField::one())),
            FoldingExp::Pow(e, 1) => e.into_compatible(),
            FoldingExp::Pow(e, i) => {
                let e = e.into_compatible();
                let mut acc = e.clone();
                for _ in 1..i {
                    acc = Mul(Box::new(e.clone()), Box::new(acc))
                }
                acc
            }
        }
    }
}

/// Used to encode the sign of a term in a polynomial.
// FIXME: is it really needed?
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Sign {
    Pos,
    Neg,
}

impl core::ops::Neg for Sign {
    type Output = Self;

    fn neg(self) -> Self {
        match self {
            Sign::Pos => Sign::Neg,
            Sign::Neg => Sign::Pos,
        }
    }
}

/// A term of a polynomial
/// For instance, in the polynomial `3 X_{1} X_{2} + 2 X_{3}`, the terms are
/// `3 X_{1} X_{2}` and `2 X_{3}`.
/// The sign is used to encode the sign of the term at the expression level.
/// It is used to split a polynomial in its terms/monomials of degree `0`, `1`
/// and `2`.
#[derive(Derivative)]
#[derivative(Debug, Clone(bound = "C: FoldingConfig"))]
pub struct Term<C: FoldingConfig> {
    pub exp: FoldingExp<C>,
    pub sign: Sign,
}

impl<C: FoldingConfig> Term<C> {
    fn double(self) -> Self {
        let Self { exp, sign } = self;
        let exp = FoldingExp::Double(Box::new(exp));
        Self { exp, sign }
    }
}

impl<C: FoldingConfig> core::ops::Mul for &Term<C> {
    type Output = Term<C>;

    fn mul(self, rhs: Self) -> Self::Output {
        let sign = if self.sign == rhs.sign {
            Sign::Pos
        } else {
            Sign::Neg
        };
        let exp = FoldingExp::Mul(Box::new(self.exp.clone()), Box::new(rhs.exp.clone()));
        Term { exp, sign }
    }
}

impl<C: FoldingConfig> core::ops::Neg for Term<C> {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Term {
            sign: -self.sign,
            ..self
        }
    }
}

/// A value of type [IntegratedFoldingExpr] is the result of the split of a
/// polynomial in its monomials of degree `0`, `1` and `2`.
/// It is used to compute the error terms. For an example, have a look at the
/// [top level documentation](super::expressions).
#[derive(Derivative)]
#[derivative(
    Debug(bound = "C: FoldingConfig"),
    Clone(bound = "C: FoldingConfig"),
    Default(bound = "C: FoldingConfig")
)]
pub struct IntegratedFoldingExpr<C: FoldingConfig> {
    // (exp,sign,alpha)
    pub(super) degree_0: Vec<(FoldingExp<C>, Sign, usize)>,
    pub(super) degree_1: Vec<(FoldingExp<C>, Sign, usize)>,
    pub(super) degree_2: Vec<(FoldingExp<C>, Sign, usize)>,
}

impl<C: FoldingConfig> IntegratedFoldingExpr<C> {
    /// Combines constraints into single expression
    pub fn final_expression(self) -> FoldingCompatibleExpr<C> {
        use FoldingCompatibleExpr::*;
        /// TODO: should use powers of alpha
        use FoldingCompatibleExprInner::*;
        let Self {
            degree_0,
            degree_1,
            degree_2,
        } = self;
        let [d0, d1, d2] = [degree_0, degree_1, degree_2]
            .map(|exps| {
                let init =
                    FoldingExp::Atom(ExtendedFoldingColumn::Constant(ScalarField::<C>::zero()));
                exps.into_iter().fold(init, |acc, (exp, sign, alpha)| {
                    let exp = FoldingExp::Mul(
                        Box::new(exp),
                        Box::new(FoldingExp::Atom(ExtendedFoldingColumn::Alpha(alpha))),
                    );
                    match sign {
                        Sign::Pos => FoldingExp::Add(Box::new(acc), Box::new(exp)),
                        Sign::Neg => FoldingExp::Sub(Box::new(acc), Box::new(exp)),
                    }
                })
            })
            .map(|e| e.into_compatible());
        let u = || Box::new(Atom(Extensions(ExpExtension::U)));
        let u2 = || Box::new(Square(u()));
        let d0 = FoldingCompatibleExpr::Mul(Box::new(d0), u2());
        let d1 = FoldingCompatibleExpr::Mul(Box::new(d1), u());
        let d2 = Box::new(d2);
        let exp = FoldingCompatibleExpr::Add(Box::new(d0), Box::new(d1));
        let exp = FoldingCompatibleExpr::Add(Box::new(exp), d2);
        FoldingCompatibleExpr::Add(
            Box::new(exp),
            Box::new(Atom(Extensions(ExpExtension::Error))),
        )
    }
}

pub fn extract_terms<C: FoldingConfig>(exp: FoldingExp<C>) -> Box<dyn Iterator<Item = Term<C>>> {
    use FoldingExp::*;
    let exps: Box<dyn Iterator<Item = Term<C>>> = match exp {
        exp @ Atom(_) => Box::new(
            [Term {
                exp,
                sign: Sign::Pos,
            }]
            .into_iter(),
        ),
        Double(exp) => Box::new(extract_terms(*exp).map(Term::double)),
        Square(exp) => {
            let terms = extract_terms(*exp).collect_vec();
            let mut combinations = Vec::with_capacity(terms.len() ^ 2);
            for t1 in terms.iter() {
                for t2 in terms.iter() {
                    combinations.push(t1 * t2)
                }
            }
            Box::new(combinations.into_iter())
        }
        Add(e1, e2) => {
            let e1 = extract_terms(*e1);
            let e2 = extract_terms(*e2);
            Box::new(e1.chain(e2))
        }
        Sub(e1, e2) => {
            let e1 = extract_terms(*e1);
            let e2 = extract_terms(*e2).map(|t| -t);
            Box::new(e1.chain(e2))
        }
        Mul(e1, e2) => {
            let e1 = extract_terms(*e1).collect_vec();
            let e2 = extract_terms(*e2).collect_vec();
            let mut combinations = Vec::with_capacity(e1.len() * e2.len());
            for t1 in e1.iter() {
                for t2 in e2.iter() {
                    combinations.push(t1 * t2)
                }
            }
            Box::new(combinations.into_iter())
        }
        Pow(_, 0) => Box::new(
            [Term {
                exp: FoldingExp::Atom(ExtendedFoldingColumn::Constant(
                    <C::Curve as AffineRepr>::ScalarField::one(),
                )),
                sign: Sign::Pos,
            }]
            .into_iter(),
        ),
        Pow(e, 1) => extract_terms(*e),
        Pow(e, mut i) => {
            let e = extract_terms(*e).collect_vec();
            let mut acc = e.clone();
            // Could do this inplace, but it's more annoying to write
            while i > 2 {
                let mut combinations = Vec::with_capacity(e.len() * acc.len());
                for t1 in e.iter() {
                    for t2 in acc.iter() {
                        combinations.push(t1 * t2)
                    }
                }
                acc = combinations;
                i -= 1;
            }
            Box::new(acc.into_iter())
        }
    };
    exps
}

/// Convert a list of folding compatible expression into the folded form.
pub fn folding_expression<C: FoldingConfig>(
    exps: Vec<FoldingCompatibleExpr<C>>,
) -> (IntegratedFoldingExpr<C>, ExtendedWitnessGenerator<C>, usize) {
    let simplified_expressions = exps.into_iter().map(|exp| exp.simplify()).collect_vec();
    let (
        Quadraticized {
            original_constraints: expressions,
            extra_constraints: extra_expressions,
            extended_witness_generator,
        },
        added_columns,
    ) = quadraticize(simplified_expressions);
    let mut terms = vec![];
    let mut alpha = 0;
    // Alpha is always increased, equal to the total number of
    // expressions. We could optimise it and only assign increasing
    // alphas in "blocks" that depend on selectors. This would make
    // #alphas equal to the expressions in the biggest block (+ some
    // columns common for all blocks of the circuit).
    for exp in expressions.into_iter() {
        terms.extend(extract_terms(exp).map(|term| (term, alpha)));
        alpha += 1;
    }
    for exp in extra_expressions.into_iter() {
        terms.extend(extract_terms(exp).map(|term| (term, alpha)));
        alpha += 1;
    }
    let mut integrated = IntegratedFoldingExpr::default();
    for (term, alpha) in terms.into_iter() {
        let Term { exp, sign } = term;
        let degree = exp.folding_degree();
        let t = (exp, sign, alpha);
        match degree {
            Degree::Zero => integrated.degree_0.push(t),
            Degree::One => integrated.degree_1.push(t),
            Degree::Two => integrated.degree_2.push(t),
        }
    }
    (integrated, extended_witness_generator, added_columns)
}

// CONVERSIONS FROM EXPR TO FOLDING COMPATIBLE EXPRESSIONS

impl<F, Config: FoldingConfig> From<ConstantExprInner<F, BerkeleyChallengeTerm>>
    for FoldingCompatibleExprInner<Config>
where
    Config::Curve: AffineRepr<ScalarField = F>,
    Config::Challenge: From<BerkeleyChallengeTerm>,
{
    fn from(expr: ConstantExprInner<F, BerkeleyChallengeTerm>) -> Self {
        match expr {
            ConstantExprInner::Challenge(chal) => {
                FoldingCompatibleExprInner::Challenge(chal.into())
            }
            ConstantExprInner::Constant(c) => match c {
                ConstantTerm::Literal(f) => FoldingCompatibleExprInner::Constant(f),
                ConstantTerm::EndoCoefficient | ConstantTerm::Mds { row: _, col: _ } => {
                    panic!("When special constants are involved, don't forget to simplify the expression before.")
                }
            },
        }
    }
}

impl<F, Col, Config: FoldingConfig<Column = Col>>
    From<ExprInner<ConstantExprInner<F, BerkeleyChallengeTerm>, Col>>
    for FoldingCompatibleExprInner<Config>
where
    Config::Curve: AffineRepr<ScalarField = F>,
    Config::Challenge: From<BerkeleyChallengeTerm>,
{
    // TODO: check if this needs some special treatment for Extensions
    fn from(expr: ExprInner<ConstantExprInner<F, BerkeleyChallengeTerm>, Col>) -> Self {
        match expr {
            ExprInner::Constant(cexpr) => cexpr.into(),
            ExprInner::Cell(col) => FoldingCompatibleExprInner::Cell(col),
            ExprInner::UnnormalizedLagrangeBasis(_) => {
                panic!("UnnormalizedLagrangeBasis should not be used in folding expressions")
            }
            ExprInner::VanishesOnZeroKnowledgeAndPreviousRows => {
                panic!("VanishesOnZeroKnowledgeAndPreviousRows should not be used in folding expressions")
            }
        }
    }
}

impl<F, Col, Config: FoldingConfig<Column = Col>>
    From<Operations<ExprInner<ConstantExprInner<F, BerkeleyChallengeTerm>, Col>>>
    for FoldingCompatibleExpr<Config>
where
    Config::Curve: AffineRepr<ScalarField = F>,
    Config::Challenge: From<BerkeleyChallengeTerm>,
{
    fn from(expr: Operations<ExprInner<ConstantExprInner<F, BerkeleyChallengeTerm>, Col>>) -> Self {
        match expr {
            Operations::Atom(inner) => FoldingCompatibleExpr::Atom(inner.into()),
            Operations::Add(x, y) => {
                FoldingCompatibleExpr::Add(Box::new((*x).into()), Box::new((*y).into()))
            }
            Operations::Mul(x, y) => {
                FoldingCompatibleExpr::Mul(Box::new((*x).into()), Box::new((*y).into()))
            }
            Operations::Sub(x, y) => {
                FoldingCompatibleExpr::Sub(Box::new((*x).into()), Box::new((*y).into()))
            }
            Operations::Double(x) => FoldingCompatibleExpr::Double(Box::new((*x).into())),
            Operations::Square(x) => FoldingCompatibleExpr::Square(Box::new((*x).into())),
            Operations::Pow(e, p) => FoldingCompatibleExpr::Pow(Box::new((*e).into()), p),
            _ => panic!("Operation not supported in folding expressions"),
        }
    }
}

impl<F, Col, Config: FoldingConfig<Column = Col>>
    From<Operations<ConstantExprInner<F, BerkeleyChallengeTerm>>> for FoldingCompatibleExpr<Config>
where
    Config::Curve: AffineRepr<ScalarField = F>,
    Config::Challenge: From<BerkeleyChallengeTerm>,
{
    fn from(expr: Operations<ConstantExprInner<F, BerkeleyChallengeTerm>>) -> Self {
        match expr {
            Operations::Add(x, y) => {
                FoldingCompatibleExpr::Add(Box::new((*x).into()), Box::new((*y).into()))
            }
            Operations::Mul(x, y) => {
                FoldingCompatibleExpr::Mul(Box::new((*x).into()), Box::new((*y).into()))
            }
            Operations::Sub(x, y) => {
                FoldingCompatibleExpr::Sub(Box::new((*x).into()), Box::new((*y).into()))
            }
            Operations::Double(x) => FoldingCompatibleExpr::Double(Box::new((*x).into())),
            Operations::Square(x) => FoldingCompatibleExpr::Square(Box::new((*x).into())),
            Operations::Pow(e, p) => FoldingCompatibleExpr::Pow(Box::new((*e).into()), p),
            _ => panic!("Operation not supported in folding expressions"),
        }
    }
}

impl<F, Col, Config: FoldingConfig<Column = Col>>
    From<Operations<ExprInner<Operations<ConstantExprInner<F, BerkeleyChallengeTerm>>, Col>>>
    for FoldingCompatibleExpr<Config>
where
    Config::Curve: AffineRepr<ScalarField = F>,
    Config::Challenge: From<BerkeleyChallengeTerm>,
{
    fn from(
        expr: Operations<ExprInner<Operations<ConstantExprInner<F, BerkeleyChallengeTerm>>, Col>>,
    ) -> Self {
        match expr {
            Operations::Atom(inner) => match inner {
                ExprInner::Constant(op) => match op {
                    // The constant expressions nodes are considered as top level
                    // expressions in folding
                    Operations::Atom(inner) => FoldingCompatibleExpr::Atom(inner.into()),
                    Operations::Add(x, y) => {
                        FoldingCompatibleExpr::Add(Box::new((*x).into()), Box::new((*y).into()))
                    }
                    Operations::Mul(x, y) => {
                        FoldingCompatibleExpr::Mul(Box::new((*x).into()), Box::new((*y).into()))
                    }
                    Operations::Sub(x, y) => {
                        FoldingCompatibleExpr::Sub(Box::new((*x).into()), Box::new((*y).into()))
                    }
                    Operations::Double(x) => FoldingCompatibleExpr::Double(Box::new((*x).into())),
                    Operations::Square(x) => FoldingCompatibleExpr::Square(Box::new((*x).into())),
                    Operations::Pow(e, p) => FoldingCompatibleExpr::Pow(Box::new((*e).into()), p),
                    _ => panic!("Operation not supported in folding expressions"),
                },
                ExprInner::Cell(col) => {
                    FoldingCompatibleExpr::Atom(FoldingCompatibleExprInner::Cell(col))
                }
                ExprInner::UnnormalizedLagrangeBasis(_) => {
                    panic!("UnnormalizedLagrangeBasis should not be used in folding expressions")
                }
                ExprInner::VanishesOnZeroKnowledgeAndPreviousRows => {
                    panic!("VanishesOnZeroKnowledgeAndPreviousRows should not be used in folding expressions")
                }
            },
            Operations::Add(x, y) => {
                FoldingCompatibleExpr::Add(Box::new((*x).into()), Box::new((*y).into()))
            }
            Operations::Mul(x, y) => {
                FoldingCompatibleExpr::Mul(Box::new((*x).into()), Box::new((*y).into()))
            }
            Operations::Sub(x, y) => {
                FoldingCompatibleExpr::Sub(Box::new((*x).into()), Box::new((*y).into()))
            }
            Operations::Double(x) => FoldingCompatibleExpr::Double(Box::new((*x).into())),
            Operations::Square(x) => FoldingCompatibleExpr::Square(Box::new((*x).into())),
            Operations::Pow(e, p) => FoldingCompatibleExpr::Pow(Box::new((*e).into()), p),
            _ => panic!("Operation not supported in folding expressions"),
        }
    }
}
