use crate::{
    circuits::{
        berkeley_columns,
        berkeley_columns::BerkeleyChallengeTerm,
        constraints::FeatureFlags,
        domains::Domain,
        gate::CurrOrNext,
        lookup::lookups::{LookupPattern, LookupPatterns},
        polynomials::{
            foreign_field_common::KimchiForeignElement, permutation::eval_vanishes_on_last_n_rows,
        },
    },
    proof::PointEvaluations,
};
use ark_ff::{FftField, Field, One, PrimeField, Zero};
use ark_poly::{
    univariate::DensePolynomial, EvaluationDomain, Evaluations, Radix2EvaluationDomain as D,
};
use core::{
    cmp::Ordering,
    fmt,
    fmt::{Debug, Display},
    iter::FromIterator,
    ops::{Add, AddAssign, Index, Mul, MulAssign, Neg, Sub},
};
use itertools::Itertools;
use o1_utils::{field_helpers::pows, foreign_field::ForeignFieldHelpers, FieldHelpers};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use thiserror::Error;
use CurrOrNext::{Curr, Next};

use self::constraints::ExprOps;

#[derive(Debug, Error)]
pub enum ExprError<Column> {
    #[error("Empty stack")]
    EmptyStack,

    #[error("Lookup should not have been used")]
    LookupShouldNotBeUsed,

    #[error("Linearization failed (needed {0:?} evaluated at the {1:?} row")]
    MissingEvaluation(Column, CurrOrNext),

    #[error("Cannot get index evaluation {0:?} (should have been linearized away)")]
    MissingIndexEvaluation(Column),

    #[error("Linearization failed (too many unevaluated columns: {0:?}")]
    FailedLinearization(Vec<Variable<Column>>),

    #[error("runtime table not available")]
    MissingRuntime,
}

/// The Challenge term that contains an alpha.
/// Is used to make a random linear combination of constraints
pub trait AlphaChallengeTerm<'a>:
    Copy + Clone + Debug + PartialEq + Eq + Serialize + Deserialize<'a> + Display
{
    const ALPHA: Self;
}

/// The collection of constants required to evaluate an `Expr`.
#[derive(Clone)]
pub struct Constants<F: 'static> {
    /// The endomorphism coefficient
    pub endo_coefficient: F,
    /// The MDS matrix
    pub mds: &'static [[F; 3]; 3],
    /// The number of zero-knowledge rows
    pub zk_rows: u64,
}

pub trait ColumnEnvironment<
    'a,
    F: FftField,
    ChallengeTerm,
    Challenges: Index<ChallengeTerm, Output = F>,
>
{
    /// The generic type of column the environment can use.
    /// In other words, with the multi-variate polynomial analogy, it is the
    /// variables the multi-variate polynomials are defined upon.
    /// i.e. for a polynomial `P(X, Y, Z)`, the type will represent the variable
    /// `X`, `Y` and `Z`.
    type Column;

    /// Return the evaluation of the given column, over the domain.
    fn get_column(&self, col: &Self::Column) -> Option<&'a Evaluations<F, D<F>>>;

    /// Defines the domain over which the column is evaluated
    fn column_domain(&self, col: &Self::Column) -> Domain;

    fn get_domain(&self, d: Domain) -> D<F>;

    /// Return the constants parameters that the expression might use.
    /// For instance, it can be the matrix used by the linear layer in the
    /// permutation.
    fn get_constants(&self) -> &Constants<F>;

    /// Return the challenges, coined by the verifier.
    fn get_challenges(&self) -> &Challenges;

    fn vanishes_on_zero_knowledge_and_previous_rows(&self) -> &'a Evaluations<F, D<F>>;

    /// Return the value `prod_{j != 1} (1 - omega^j)`, used for efficiently
    /// computing the evaluations of the unnormalized Lagrange basis polynomials.
    fn l0_1(&self) -> F;
}

// In this file, we define...
//
//     The unnormalized lagrange polynomial
//
//         l_i(x) = (x^n - 1) / (x - omega^i) = prod_{j != i} (x - omega^j)
//
//     and the normalized lagrange polynomial
//
//         L_i(x) = l_i(x) / l_i(omega^i)

/// Computes `prod_{j != n} (1 - omega^j)`
///     Assure we don't multiply by (1 - omega^n) = (1 - omega^0) = (1 - 1) = 0
pub fn l0_1<F: FftField>(d: D<F>) -> F {
    d.elements()
        .skip(1)
        .fold(F::one(), |acc, omega_j| acc * (F::one() - omega_j))
}

// Compute the ith unnormalized lagrange basis
pub fn unnormalized_lagrange_basis<F: FftField>(domain: &D<F>, i: i32, pt: &F) -> F {
    let omega_i = if i < 0 {
        domain.group_gen.pow([-i as u64]).inverse().unwrap()
    } else {
        domain.group_gen.pow([i as u64])
    };
    domain.evaluate_vanishing_polynomial(*pt) / (*pt - omega_i)
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
/// A type representing a variable which can appear in a constraint. It specifies a column
/// and a relative position (Curr or Next)
pub struct Variable<Column> {
    /// The column of this variable
    pub col: Column,
    /// The row (Curr of Next) of this variable
    pub row: CurrOrNext,
}

/// Define the constant terms an expression can use.
/// It can be any constant term (`Literal`), a matrix (`Mds` - used by the
/// permutation used by Poseidon for instance), or endomorphism coefficients
/// (`EndoCoefficient` - used as an optimisation).
/// As for `challengeTerm`, it has been used initially to implement the PLONK
/// IOP, with the custom gate Poseidon. However, the terms have no built-in
/// semantic in the expression framework.
/// TODO: we should generalize the expression type over challenges and constants.
/// See <https://github.com/MinaProtocol/mina/issues/15287>
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConstantTerm<F> {
    EndoCoefficient,
    Mds { row: usize, col: usize },
    Literal(F),
}

pub trait Literal: Sized + Clone {
    type F;

    fn literal(x: Self::F) -> Self;

    fn to_literal(self) -> Result<Self::F, Self>;

    fn to_literal_ref(&self) -> Option<&Self::F>;

    /// Obtains the representation of some constants as a literal.
    /// This is useful before converting Kimchi expressions with constants
    /// to folding compatible expressions.
    fn as_literal(&self, constants: &Constants<Self::F>) -> Self;
}

impl<F: Field> Literal for F {
    type F = F;

    fn literal(x: Self::F) -> Self {
        x
    }

    fn to_literal(self) -> Result<Self::F, Self> {
        Ok(self)
    }

    fn to_literal_ref(&self) -> Option<&Self::F> {
        Some(self)
    }

    fn as_literal(&self, _constants: &Constants<Self::F>) -> Self {
        *self
    }
}

impl<F: Clone> Literal for ConstantTerm<F> {
    type F = F;
    fn literal(x: Self::F) -> Self {
        ConstantTerm::Literal(x)
    }
    fn to_literal(self) -> Result<Self::F, Self> {
        match self {
            ConstantTerm::Literal(x) => Ok(x),
            x => Err(x),
        }
    }
    fn to_literal_ref(&self) -> Option<&Self::F> {
        match self {
            ConstantTerm::Literal(x) => Some(x),
            _ => None,
        }
    }
    fn as_literal(&self, constants: &Constants<Self::F>) -> Self {
        match self {
            ConstantTerm::EndoCoefficient => {
                ConstantTerm::Literal(constants.endo_coefficient.clone())
            }
            ConstantTerm::Mds { row, col } => {
                ConstantTerm::Literal(constants.mds[*row][*col].clone())
            }
            ConstantTerm::Literal(_) => self.clone(),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum ConstantExprInner<F, ChallengeTerm> {
    Challenge(ChallengeTerm),
    Constant(ConstantTerm<F>),
}

impl<'a, F: Clone, ChallengeTerm: AlphaChallengeTerm<'a>> Literal
    for ConstantExprInner<F, ChallengeTerm>
{
    type F = F;
    fn literal(x: Self::F) -> Self {
        Self::Constant(ConstantTerm::literal(x))
    }
    fn to_literal(self) -> Result<Self::F, Self> {
        match self {
            Self::Constant(x) => match x.to_literal() {
                Ok(x) => Ok(x),
                Err(x) => Err(Self::Constant(x)),
            },
            x => Err(x),
        }
    }
    fn to_literal_ref(&self) -> Option<&Self::F> {
        match self {
            Self::Constant(x) => x.to_literal_ref(),
            _ => None,
        }
    }
    fn as_literal(&self, constants: &Constants<Self::F>) -> Self {
        match self {
            Self::Constant(x) => Self::Constant(x.as_literal(constants)),
            Self::Challenge(_) => self.clone(),
        }
    }
}

impl<'a, F, ChallengeTerm: AlphaChallengeTerm<'a>> From<ChallengeTerm>
    for ConstantExprInner<F, ChallengeTerm>
{
    fn from(x: ChallengeTerm) -> Self {
        ConstantExprInner::Challenge(x)
    }
}

impl<F, ChallengeTerm> From<ConstantTerm<F>> for ConstantExprInner<F, ChallengeTerm> {
    fn from(x: ConstantTerm<F>) -> Self {
        ConstantExprInner::Constant(x)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Operations<T> {
    Atom(T),
    Pow(Box<Self>, u64),
    Add(Box<Self>, Box<Self>),
    Mul(Box<Self>, Box<Self>),
    Sub(Box<Self>, Box<Self>),
    Double(Box<Self>),
    Square(Box<Self>),
    Cache(CacheId, Box<Self>),
    IfFeature(FeatureFlag, Box<Self>, Box<Self>),
}

impl<T> From<T> for Operations<T> {
    fn from(x: T) -> Self {
        Operations::Atom(x)
    }
}

impl<T: Literal + Clone> Literal for Operations<T> {
    type F = T::F;

    fn literal(x: Self::F) -> Self {
        Self::Atom(T::literal(x))
    }

    fn to_literal(self) -> Result<Self::F, Self> {
        match self {
            Self::Atom(x) => match x.to_literal() {
                Ok(x) => Ok(x),
                Err(x) => Err(Self::Atom(x)),
            },
            x => Err(x),
        }
    }

    fn to_literal_ref(&self) -> Option<&Self::F> {
        match self {
            Self::Atom(x) => x.to_literal_ref(),
            _ => None,
        }
    }

    fn as_literal(&self, constants: &Constants<Self::F>) -> Self {
        match self {
            Self::Atom(x) => Self::Atom(x.as_literal(constants)),
            Self::Pow(x, n) => Self::Pow(Box::new(x.as_literal(constants)), *n),
            Self::Add(x, y) => Self::Add(
                Box::new(x.as_literal(constants)),
                Box::new(y.as_literal(constants)),
            ),
            Self::Mul(x, y) => Self::Mul(
                Box::new(x.as_literal(constants)),
                Box::new(y.as_literal(constants)),
            ),
            Self::Sub(x, y) => Self::Sub(
                Box::new(x.as_literal(constants)),
                Box::new(y.as_literal(constants)),
            ),
            Self::Double(x) => Self::Double(Box::new(x.as_literal(constants))),
            Self::Square(x) => Self::Square(Box::new(x.as_literal(constants))),
            Self::Cache(id, x) => Self::Cache(*id, Box::new(x.as_literal(constants))),
            Self::IfFeature(flag, if_true, if_false) => Self::IfFeature(
                *flag,
                Box::new(if_true.as_literal(constants)),
                Box::new(if_false.as_literal(constants)),
            ),
        }
    }
}

pub type ConstantExpr<F, ChallengeTerm> = Operations<ConstantExprInner<F, ChallengeTerm>>;

impl<F, ChallengeTerm> From<ConstantTerm<F>> for ConstantExpr<F, ChallengeTerm> {
    fn from(x: ConstantTerm<F>) -> Self {
        ConstantExprInner::from(x).into()
    }
}

impl<'a, F, ChallengeTerm: AlphaChallengeTerm<'a>> From<ChallengeTerm>
    for ConstantExpr<F, ChallengeTerm>
{
    fn from(x: ChallengeTerm) -> Self {
        ConstantExprInner::from(x).into()
    }
}

impl<F: Copy, ChallengeTerm: Copy> ConstantExprInner<F, ChallengeTerm> {
    fn to_polish<Column>(
        &self,
        _cache: &mut HashMap<CacheId, usize>,
        res: &mut Vec<PolishToken<F, Column, ChallengeTerm>>,
    ) {
        match self {
            ConstantExprInner::Challenge(chal) => res.push(PolishToken::Challenge(*chal)),
            ConstantExprInner::Constant(c) => res.push(PolishToken::Constant(*c)),
        }
    }
}

impl<F: Copy, ChallengeTerm: Copy> Operations<ConstantExprInner<F, ChallengeTerm>> {
    fn to_polish<Column>(
        &self,
        cache: &mut HashMap<CacheId, usize>,
        res: &mut Vec<PolishToken<F, Column, ChallengeTerm>>,
    ) {
        match self {
            Operations::Atom(atom) => atom.to_polish(cache, res),
            Operations::Add(x, y) => {
                x.as_ref().to_polish(cache, res);
                y.as_ref().to_polish(cache, res);
                res.push(PolishToken::Add)
            }
            Operations::Mul(x, y) => {
                x.as_ref().to_polish(cache, res);
                y.as_ref().to_polish(cache, res);
                res.push(PolishToken::Mul)
            }
            Operations::Sub(x, y) => {
                x.as_ref().to_polish(cache, res);
                y.as_ref().to_polish(cache, res);
                res.push(PolishToken::Sub)
            }
            Operations::Pow(x, n) => {
                x.to_polish(cache, res);
                res.push(PolishToken::Pow(*n))
            }
            Operations::Double(x) => {
                x.to_polish(cache, res);
                res.push(PolishToken::Dup);
                res.push(PolishToken::Add);
            }
            Operations::Square(x) => {
                x.to_polish(cache, res);
                res.push(PolishToken::Dup);
                res.push(PolishToken::Mul);
            }
            Operations::Cache(id, x) => {
                match cache.get(id) {
                    Some(pos) =>
                    // Already computed and stored this.
                    {
                        res.push(PolishToken::Load(*pos))
                    }
                    None => {
                        // Haven't computed this yet. Compute it, then store it.
                        x.to_polish(cache, res);
                        res.push(PolishToken::Store);
                        cache.insert(*id, cache.len());
                    }
                }
            }
            Operations::IfFeature(feature, if_true, if_false) => {
                {
                    // True branch
                    let tok = PolishToken::SkipIfNot(*feature, 0);
                    res.push(tok);
                    let len_before = res.len();
                    /* Clone the cache, to make sure we don't try to access cached statements later
                    when the feature flag is off. */
                    let mut cache = cache.clone();
                    if_true.to_polish(&mut cache, res);
                    let len_after = res.len();
                    res[len_before - 1] = PolishToken::SkipIfNot(*feature, len_after - len_before);
                }

                {
                    // False branch
                    let tok = PolishToken::SkipIfNot(*feature, 0);
                    res.push(tok);
                    let len_before = res.len();
                    /* Clone the cache, to make sure we don't try to access cached statements later
                    when the feature flag is on. */
                    let mut cache = cache.clone();
                    if_false.to_polish(&mut cache, res);
                    let len_after = res.len();
                    res[len_before - 1] = PolishToken::SkipIfNot(*feature, len_after - len_before);
                }
            }
        }
    }
}

impl<T: Literal> Operations<T>
where
    T::F: Field,
{
    /// Exponentiate a constant expression.
    pub fn pow(self, p: u64) -> Self {
        if p == 0 {
            return Self::literal(T::F::one());
        }
        match self.to_literal() {
            Ok(l) => Self::literal(<T::F as Field>::pow(&l, [p])),
            Err(x) => Self::Pow(Box::new(x), p),
        }
    }
}

impl<F: Field, ChallengeTerm: Copy> ConstantExpr<F, ChallengeTerm> {
    /// Evaluate the given constant expression to a field element.
    pub fn value(&self, c: &Constants<F>, chals: &dyn Index<ChallengeTerm, Output = F>) -> F {
        use ConstantExprInner::*;
        use Operations::*;
        match self {
            Atom(Challenge(challenge_term)) => chals[*challenge_term],
            Atom(Constant(ConstantTerm::EndoCoefficient)) => c.endo_coefficient,
            Atom(Constant(ConstantTerm::Mds { row, col })) => c.mds[*row][*col],
            Atom(Constant(ConstantTerm::Literal(x))) => *x,
            Pow(x, p) => x.value(c, chals).pow([*p]),
            Mul(x, y) => x.value(c, chals) * y.value(c, chals),
            Add(x, y) => x.value(c, chals) + y.value(c, chals),
            Sub(x, y) => x.value(c, chals) - y.value(c, chals),
            Double(x) => x.value(c, chals).double(),
            Square(x) => x.value(c, chals).square(),
            Cache(_, x) => {
                // TODO: Use cache ID
                x.value(c, chals)
            }
            IfFeature(_flag, _if_true, _if_false) => todo!(),
        }
    }
}

/// A key for a cached value
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CacheId(usize);

/// A cache
#[derive(Default)]
pub struct Cache {
    next_id: usize,
}

impl CacheId {
    fn get_from<'b, F: FftField>(
        &self,
        cache: &'b HashMap<CacheId, EvalResult<'_, F>>,
    ) -> Option<EvalResult<'b, F>> {
        cache.get(self).map(|e| match e {
            EvalResult::Constant(x) => EvalResult::Constant(*x),
            EvalResult::SubEvals {
                domain,
                shift,
                evals,
            } => EvalResult::SubEvals {
                domain: *domain,
                shift: *shift,
                evals,
            },
            EvalResult::Evals { domain, evals } => EvalResult::SubEvals {
                domain: *domain,
                shift: 0,
                evals,
            },
        })
    }

    fn var_name(&self) -> String {
        format!("x_{}", self.0)
    }

    fn latex_name(&self) -> String {
        format!("x_{{{}}}", self.0)
    }
}

impl Cache {
    fn next_id(&mut self) -> CacheId {
        let id = self.next_id;
        self.next_id += 1;
        CacheId(id)
    }

    pub fn cache<F: Field, ChallengeTerm, T: ExprOps<F, ChallengeTerm>>(&mut self, e: T) -> T {
        e.cache(self)
    }
}

/// The feature flags that can be used to enable or disable parts of constraints.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
#[cfg_attr(
    feature = "ocaml_types",
    derive(ocaml::IntoValue, ocaml::FromValue, ocaml_gen::Enum)
)]
pub enum FeatureFlag {
    RangeCheck0,
    RangeCheck1,
    ForeignFieldAdd,
    ForeignFieldMul,
    Xor,
    Rot,
    LookupTables,
    RuntimeLookupTables,
    LookupPattern(LookupPattern),
    /// Enabled if the table width is at least the given number
    TableWidth(isize), // NB: isize so that we don't need to convert for OCaml :(
    /// Enabled if the number of lookups per row is at least the given number
    LookupsPerRow(isize), // NB: isize so that we don't need to convert for OCaml :(
}

impl FeatureFlag {
    fn is_enabled(&self) -> bool {
        todo!("Handle features")
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RowOffset {
    pub zk_rows: bool,
    pub offset: i32,
}

#[derive(Clone, Debug, PartialEq)]
pub enum ExprInner<C, Column> {
    Constant(C),
    Cell(Variable<Column>),
    VanishesOnZeroKnowledgeAndPreviousRows,
    /// UnnormalizedLagrangeBasis(i) is
    /// (x^n - 1) / (x - omega^i)
    UnnormalizedLagrangeBasis(RowOffset),
}

/// An multi-variate polynomial over the base ring `C` with
/// variables
///
/// - `Cell(v)` for `v : Variable`
/// - VanishesOnZeroKnowledgeAndPreviousRows
/// - UnnormalizedLagrangeBasis(i) for `i : i32`
///
/// This represents a PLONK "custom constraint", which enforces that
/// the corresponding combination of the polynomials corresponding to
/// the above variables should vanish on the PLONK domain.
pub type Expr<C, Column> = Operations<ExprInner<C, Column>>;

impl<F, Column, ChallengeTerm> From<ConstantExpr<F, ChallengeTerm>>
    for Expr<ConstantExpr<F, ChallengeTerm>, Column>
{
    fn from(x: ConstantExpr<F, ChallengeTerm>) -> Self {
        Expr::Atom(ExprInner::Constant(x))
    }
}

impl<'a, F, Column, ChallengeTerm: AlphaChallengeTerm<'a>> From<ConstantTerm<F>>
    for Expr<ConstantExpr<F, ChallengeTerm>, Column>
{
    fn from(x: ConstantTerm<F>) -> Self {
        ConstantExpr::from(x).into()
    }
}

impl<'a, F, Column, ChallengeTerm: AlphaChallengeTerm<'a>> From<ChallengeTerm>
    for Expr<ConstantExpr<F, ChallengeTerm>, Column>
{
    fn from(x: ChallengeTerm) -> Self {
        ConstantExpr::from(x).into()
    }
}

impl<T: Literal, Column: Clone> Literal for ExprInner<T, Column> {
    type F = T::F;

    fn literal(x: Self::F) -> Self {
        ExprInner::Constant(T::literal(x))
    }

    fn to_literal(self) -> Result<Self::F, Self> {
        match self {
            ExprInner::Constant(x) => match x.to_literal() {
                Ok(x) => Ok(x),
                Err(x) => Err(ExprInner::Constant(x)),
            },
            x => Err(x),
        }
    }

    fn to_literal_ref(&self) -> Option<&Self::F> {
        match self {
            ExprInner::Constant(x) => x.to_literal_ref(),
            _ => None,
        }
    }

    fn as_literal(&self, constants: &Constants<Self::F>) -> Self {
        match self {
            ExprInner::Constant(x) => ExprInner::Constant(x.as_literal(constants)),
            ExprInner::Cell(_)
            | ExprInner::VanishesOnZeroKnowledgeAndPreviousRows
            | ExprInner::UnnormalizedLagrangeBasis(_) => self.clone(),
        }
    }
}

impl<T: Literal + PartialEq> Operations<T>
where
    T::F: Field,
{
    fn apply_feature_flags_inner(&self, features: &FeatureFlags) -> (Self, bool) {
        use Operations::*;
        match self {
            Atom(_) => (self.clone(), false),
            Double(c) => {
                let (c_reduced, reduce_further) = c.apply_feature_flags_inner(features);
                if reduce_further && c_reduced.is_zero() {
                    (Self::zero(), true)
                } else {
                    (Double(Box::new(c_reduced)), false)
                }
            }
            Square(c) => {
                let (c_reduced, reduce_further) = c.apply_feature_flags_inner(features);
                if reduce_further && (c_reduced.is_zero() || c_reduced.is_one()) {
                    (c_reduced, true)
                } else {
                    (Square(Box::new(c_reduced)), false)
                }
            }
            Add(c1, c2) => {
                let (c1_reduced, reduce_further1) = c1.apply_feature_flags_inner(features);
                let (c2_reduced, reduce_further2) = c2.apply_feature_flags_inner(features);
                if reduce_further1 && c1_reduced.is_zero() {
                    if reduce_further2 && c2_reduced.is_zero() {
                        (Self::zero(), true)
                    } else {
                        (c2_reduced, false)
                    }
                } else if reduce_further2 && c2_reduced.is_zero() {
                    (c1_reduced, false)
                } else {
                    (Add(Box::new(c1_reduced), Box::new(c2_reduced)), false)
                }
            }
            Sub(c1, c2) => {
                let (c1_reduced, reduce_further1) = c1.apply_feature_flags_inner(features);
                let (c2_reduced, reduce_further2) = c2.apply_feature_flags_inner(features);
                if reduce_further1 && c1_reduced.is_zero() {
                    if reduce_further2 && c2_reduced.is_zero() {
                        (Self::zero(), true)
                    } else {
                        (-c2_reduced, false)
                    }
                } else if reduce_further2 && c2_reduced.is_zero() {
                    (c1_reduced, false)
                } else {
                    (Sub(Box::new(c1_reduced), Box::new(c2_reduced)), false)
                }
            }
            Mul(c1, c2) => {
                let (c1_reduced, reduce_further1) = c1.apply_feature_flags_inner(features);
                let (c2_reduced, reduce_further2) = c2.apply_feature_flags_inner(features);
                if reduce_further1 && c1_reduced.is_zero()
                    || reduce_further2 && c2_reduced.is_zero()
                {
                    (Self::zero(), true)
                } else if reduce_further1 && c1_reduced.is_one() {
                    if reduce_further2 && c2_reduced.is_one() {
                        (Self::one(), true)
                    } else {
                        (c2_reduced, false)
                    }
                } else if reduce_further2 && c2_reduced.is_one() {
                    (c1_reduced, false)
                } else {
                    (Mul(Box::new(c1_reduced), Box::new(c2_reduced)), false)
                }
            }
            Pow(c, power) => {
                let (c_reduced, reduce_further) = c.apply_feature_flags_inner(features);
                if reduce_further && (c_reduced.is_zero() || c_reduced.is_one()) {
                    (c_reduced, true)
                } else {
                    (Pow(Box::new(c_reduced), *power), false)
                }
            }
            Cache(cache_id, c) => {
                let (c_reduced, reduce_further) = c.apply_feature_flags_inner(features);
                if reduce_further {
                    (c_reduced, true)
                } else {
                    (Cache(*cache_id, Box::new(c_reduced)), false)
                }
            }
            IfFeature(feature, c1, c2) => {
                let is_enabled = {
                    use FeatureFlag::*;
                    match feature {
                        RangeCheck0 => features.range_check0,
                        RangeCheck1 => features.range_check1,
                        ForeignFieldAdd => features.foreign_field_add,
                        ForeignFieldMul => features.foreign_field_mul,
                        Xor => features.xor,
                        Rot => features.rot,
                        LookupTables => {
                            features.lookup_features.patterns != LookupPatterns::default()
                        }
                        RuntimeLookupTables => features.lookup_features.uses_runtime_tables,
                        LookupPattern(pattern) => features.lookup_features.patterns[*pattern],
                        TableWidth(width) => features
                            .lookup_features
                            .patterns
                            .into_iter()
                            .any(|feature| feature.max_joint_size() >= (*width as u32)),
                        LookupsPerRow(count) => features
                            .lookup_features
                            .patterns
                            .into_iter()
                            .any(|feature| feature.max_lookups_per_row() >= (*count as usize)),
                    }
                };
                if is_enabled {
                    let (c1_reduced, _) = c1.apply_feature_flags_inner(features);
                    (c1_reduced, false)
                } else {
                    let (c2_reduced, _) = c2.apply_feature_flags_inner(features);
                    (c2_reduced, true)
                }
            }
        }
    }
    pub fn apply_feature_flags(&self, features: &FeatureFlags) -> Self {
        let (res, _) = self.apply_feature_flags_inner(features);
        res
    }
}

/// For efficiency of evaluation, we compile expressions to
/// [reverse Polish notation](https://en.wikipedia.org/wiki/Reverse_Polish_notation)
/// expressions, which are vectors of the below tokens.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolishToken<F, Column, ChallengeTerm> {
    Constant(ConstantTerm<F>),
    Challenge(ChallengeTerm),
    Cell(Variable<Column>),
    Dup,
    Pow(u64),
    Add,
    Mul,
    Sub,
    VanishesOnZeroKnowledgeAndPreviousRows,
    UnnormalizedLagrangeBasis(RowOffset),
    Store,
    Load(usize),
    /// Skip the given number of tokens if the feature is enabled.
    SkipIf(FeatureFlag, usize),
    /// Skip the given number of tokens if the feature is disabled.
    SkipIfNot(FeatureFlag, usize),
}

pub trait ColumnEvaluations<F> {
    type Column;
    fn evaluate(&self, col: Self::Column) -> Result<PointEvaluations<F>, ExprError<Self::Column>>;
}

impl<Column: Copy> Variable<Column> {
    fn evaluate<F: Field, Evaluations: ColumnEvaluations<F, Column = Column>>(
        &self,
        evals: &Evaluations,
    ) -> Result<F, ExprError<Column>> {
        let point_evaluations = evals.evaluate(self.col)?;
        match self.row {
            CurrOrNext::Curr => Ok(point_evaluations.zeta),
            CurrOrNext::Next => Ok(point_evaluations.zeta_omega),
        }
    }
}

impl<F: FftField, Column: Copy, ChallengeTerm: Copy> PolishToken<F, Column, ChallengeTerm> {
    /// Evaluate an RPN expression to a field element.
    pub fn evaluate<Evaluations: ColumnEvaluations<F, Column = Column>>(
        toks: &[PolishToken<F, Column, ChallengeTerm>],
        d: D<F>,
        pt: F,
        evals: &Evaluations,
        c: &Constants<F>,
        chals: &dyn Index<ChallengeTerm, Output = F>,
    ) -> Result<F, ExprError<Column>> {
        let mut stack = vec![];
        let mut cache: Vec<F> = vec![];

        let mut skip_count = 0;

        for t in toks.iter() {
            if skip_count > 0 {
                skip_count -= 1;
                continue;
            }

            use ConstantTerm::*;
            use PolishToken::*;
            match t {
                Challenge(challenge_term) => stack.push(chals[*challenge_term]),
                Constant(EndoCoefficient) => stack.push(c.endo_coefficient),
                Constant(Mds { row, col }) => stack.push(c.mds[*row][*col]),
                VanishesOnZeroKnowledgeAndPreviousRows => {
                    stack.push(eval_vanishes_on_last_n_rows(d, c.zk_rows + 1, pt))
                }
                UnnormalizedLagrangeBasis(i) => {
                    let offset = if i.zk_rows {
                        -(c.zk_rows as i32) + i.offset
                    } else {
                        i.offset
                    };
                    stack.push(unnormalized_lagrange_basis(&d, offset, &pt))
                }
                Constant(Literal(x)) => stack.push(*x),
                Dup => stack.push(stack[stack.len() - 1]),
                Cell(v) => match v.evaluate(evals) {
                    Ok(x) => stack.push(x),
                    Err(e) => return Err(e),
                },
                Pow(n) => {
                    let i = stack.len() - 1;
                    stack[i] = stack[i].pow([*n]);
                }
                Add => {
                    let y = stack.pop().ok_or(ExprError::EmptyStack)?;
                    let x = stack.pop().ok_or(ExprError::EmptyStack)?;
                    stack.push(x + y);
                }
                Mul => {
                    let y = stack.pop().ok_or(ExprError::EmptyStack)?;
                    let x = stack.pop().ok_or(ExprError::EmptyStack)?;
                    stack.push(x * y);
                }
                Sub => {
                    let y = stack.pop().ok_or(ExprError::EmptyStack)?;
                    let x = stack.pop().ok_or(ExprError::EmptyStack)?;
                    stack.push(x - y);
                }
                Store => {
                    let x = stack[stack.len() - 1];
                    cache.push(x);
                }
                Load(i) => stack.push(cache[*i]),
                SkipIf(feature, count) => {
                    if feature.is_enabled() {
                        skip_count = *count;
                        stack.push(F::zero());
                    }
                }
                SkipIfNot(feature, count) => {
                    if !feature.is_enabled() {
                        skip_count = *count;
                        stack.push(F::zero());
                    }
                }
            }
        }

        assert_eq!(stack.len(), 1);
        Ok(stack[0])
    }
}

impl<C, Column> Expr<C, Column> {
    /// Convenience function for constructing cell variables.
    pub fn cell(col: Column, row: CurrOrNext) -> Expr<C, Column> {
        Expr::Atom(ExprInner::Cell(Variable { col, row }))
    }

    pub fn double(self) -> Self {
        Expr::Double(Box::new(self))
    }

    pub fn square(self) -> Self {
        Expr::Square(Box::new(self))
    }

    /// Convenience function for constructing constant expressions.
    pub fn constant(c: C) -> Expr<C, Column> {
        Expr::Atom(ExprInner::Constant(c))
    }

    /// Return the degree of the expression.
    /// The degree of a cell is defined by the first argument `d1_size`, a
    /// constant being of degree zero. The degree of the expression is defined
    /// recursively using the definition of the degree of a multivariate
    /// polynomial. The function can be (and is) used to compute the domain
    /// size, hence the name of the first argument `d1_size`.
    /// The second parameter `zk_rows` is used to define the degree of the
    /// constructor `VanishesOnZeroKnowledgeAndPreviousRows`.
    pub fn degree(&self, d1_size: u64, zk_rows: u64) -> u64 {
        use ExprInner::*;
        use Operations::*;
        match self {
            Double(x) => x.degree(d1_size, zk_rows),
            Atom(Constant(_)) => 0,
            Atom(VanishesOnZeroKnowledgeAndPreviousRows) => zk_rows + 1,
            Atom(UnnormalizedLagrangeBasis(_)) => d1_size,
            Atom(Cell(_)) => d1_size,
            Square(x) => 2 * x.degree(d1_size, zk_rows),
            Mul(x, y) => (*x).degree(d1_size, zk_rows) + (*y).degree(d1_size, zk_rows),
            Add(x, y) | Sub(x, y) => {
                core::cmp::max((*x).degree(d1_size, zk_rows), (*y).degree(d1_size, zk_rows))
            }
            Pow(e, d) => d * e.degree(d1_size, zk_rows),
            Cache(_, e) => e.degree(d1_size, zk_rows),
            IfFeature(_, e1, e2) => {
                core::cmp::max(e1.degree(d1_size, zk_rows), e2.degree(d1_size, zk_rows))
            }
        }
    }
}

impl<'a, F, Column: FormattedOutput + Debug + Clone, ChallengeTerm> fmt::Display
    for Expr<ConstantExpr<F, ChallengeTerm>, Column>
where
    F: PrimeField,
    ChallengeTerm: AlphaChallengeTerm<'a>,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let cache = &mut HashMap::new();
        write!(f, "{}", self.text(cache))
    }
}

#[derive(Clone)]
enum EvalResult<'a, F: FftField> {
    Constant(F),
    Evals {
        domain: Domain,
        evals: Evaluations<F, D<F>>,
    },
    /// SubEvals is used to refer to evaluations that can be trivially obtained from a
    /// borrowed evaluation. In this case, by taking a subset of the entries
    /// (specifically when the borrowed `evals` is over a superset of `domain`)
    /// and shifting them
    SubEvals {
        domain: Domain,
        shift: usize,
        evals: &'a Evaluations<F, D<F>>,
    },
}

/// Compute the evaluations of the unnormalized lagrange polynomial on
/// H_8 or H_4. Taking H_8 as an example, we show how to compute this
/// polynomial on the expanded domain.
///
/// Let H = < omega >, |H| = n.
///
/// Let l_i(x) be the unnormalized lagrange polynomial,
/// (x^n - 1) / (x - omega^i)
/// = prod_{j != i} (x - omega^j)
///
/// For h in H, h != omega^i,
/// l_i(h) = 0.
/// l_i(omega^i)
/// = prod_{j != i} (omega^i - omega^j)
/// = omega^{i (n - 1)} * prod_{j != i} (1 - omega^{j - i})
/// = omega^{i (n - 1)} * prod_{j != 0} (1 - omega^j)
/// = omega^{i (n - 1)} * l_0(1)
/// = omega^{i n} * omega^{-i} * l_0(1)
/// = omega^{-i} * l_0(1)
///
/// So it is easy to compute l_i(omega^i) from just l_0(1).
///
/// Also, consider the expanded domain H_8 generated by
/// an 8nth root of unity omega_8 (where H_8^8 = H).
///
/// Let omega_8^k in H_8. Write k = 8 * q + r with r < 8.
/// Then
/// omega_8^k = (omega_8^8)^q * omega_8^r = omega^q * omega_8^r
///
/// l_i(omega_8^k)
/// = (omega_8^{k n} - 1) / (omega_8^k - omega^i)
/// = (omega^{q n} omega_8^{r n} - 1) / (omega_8^k - omega^i)
/// = ((omega_8^n)^r - 1) / (omega_8^k - omega^i)
/// = ((omega_8^n)^r - 1) / (omega^q omega_8^r - omega^i)
fn unnormalized_lagrange_evals<
    'a,
    F: FftField,
    ChallengeTerm,
    Challenge: Index<ChallengeTerm, Output = F>,
    Environment: ColumnEnvironment<'a, F, ChallengeTerm, Challenge>,
>(
    l0_1: F,
    i: i32,
    res_domain: Domain,
    env: &Environment,
) -> Evaluations<F, D<F>> {
    let k = match res_domain {
        Domain::D1 => 1,
        Domain::D2 => 2,
        Domain::D4 => 4,
        Domain::D8 => 8,
    };
    let res_domain = env.get_domain(res_domain);

    let d1 = env.get_domain(Domain::D1);
    let n = d1.size;
    // Renormalize negative values to wrap around at domain size
    let i = if i < 0 {
        ((i as isize) + (n as isize)) as usize
    } else {
        i as usize
    };
    let ii = i as u64;
    assert!(ii < n);
    let omega = d1.group_gen;
    let omega_i = omega.pow([ii]);
    let omega_minus_i = omega.pow([n - ii]);

    // Write res_domain = < omega_k > with
    // |res_domain| = k * |H|

    // omega_k^0, ..., omega_k^k
    let omega_k_n_pows = pows(k, res_domain.group_gen.pow([n]));
    let omega_k_pows = pows(k, res_domain.group_gen);

    let mut evals: Vec<F> = {
        let mut v = vec![F::one(); k * (n as usize)];
        let mut omega_q = F::one();
        for q in 0..(n as usize) {
            // omega_q == omega^q
            for r in 1..k {
                v[k * q + r] = omega_q * omega_k_pows[r] - omega_i;
            }
            omega_q *= omega;
        }
        ark_ff::fields::batch_inversion::<F>(&mut v[..]);
        v
    };
    // At this point, in the 0 mod k indices, we have dummy values,
    // and in the other indices k*q + r, we have
    // 1 / (omega^q omega_k^r - omega^i)

    // Set the 0 mod k indices
    for q in 0..(n as usize) {
        evals[k * q] = F::zero();
    }
    evals[k * i] = omega_minus_i * l0_1;

    // Finish computing the non-zero mod k indices
    for q in 0..(n as usize) {
        for r in 1..k {
            evals[k * q + r] *= omega_k_n_pows[r] - F::one();
        }
    }

    Evaluations::<F, D<F>>::from_vec_and_domain(evals, res_domain)
}

/// Implement algebraic methods like `add`, `sub`, `mul`, `square`, etc to use
/// algebra on the type `EvalResult`.
impl<'a, F: FftField> EvalResult<'a, F> {
    /// Create an evaluation over the domain `res_domain`.
    /// The second parameter, `g`, is a function used to define the
    /// evaluations at a given point of the domain.
    /// For instance, the second parameter `g` can simply be the identity
    /// functions over a set of field elements.
    /// It can also be used to define polynomials like `x^2` when we only have the
    /// value of `x`. It can be used in particular to evaluate an expression (a
    /// multi-variate polynomial) when we only do have access to the evaluations
    /// of the individual variables.
    fn init_<G: Sync + Send + Fn(usize) -> F>(
        res_domain: (Domain, D<F>),
        g: G,
    ) -> Evaluations<F, D<F>> {
        let n = res_domain.1.size();
        Evaluations::<F, D<F>>::from_vec_and_domain(
            (0..n).into_par_iter().map(g).collect(),
            res_domain.1,
        )
    }

    /// Call the internal function `init_` and return the computed evaluation as
    /// a value `Evals`.
    fn init<G: Sync + Send + Fn(usize) -> F>(res_domain: (Domain, D<F>), g: G) -> Self {
        Self::Evals {
            domain: res_domain.0,
            evals: Self::init_(res_domain, g),
        }
    }

    fn add<'c>(self, other: EvalResult<'_, F>, res_domain: (Domain, D<F>)) -> EvalResult<'c, F> {
        use EvalResult::*;
        match (self, other) {
            (Constant(x), Constant(y)) => Constant(x + y),
            (Evals { domain, mut evals }, Constant(x))
            | (Constant(x), Evals { domain, mut evals }) => {
                evals.evals.par_iter_mut().for_each(|e| *e += x);
                Evals { domain, evals }
            }
            (
                SubEvals {
                    evals,
                    domain,
                    shift,
                },
                Constant(x),
            )
            | (
                Constant(x),
                SubEvals {
                    evals,
                    domain,
                    shift,
                },
            ) => {
                let n = res_domain.1.size();
                let scale = (domain as usize) / (res_domain.0 as usize);
                assert!(
                    scale != 0,
                    "Check that the implementation of
                column_domain and the evaluation domain of the
                witnesses are the same"
                );
                let v: Vec<_> = (0..n)
                    .into_par_iter()
                    .map(|i| {
                        x + evals.evals[(scale * i + (domain as usize) * shift) % evals.evals.len()]
                    })
                    .collect();
                Evals {
                    domain: res_domain.0,
                    evals: Evaluations::<F, D<F>>::from_vec_and_domain(v, res_domain.1),
                }
            }
            (
                Evals {
                    domain: d1,
                    evals: mut es1,
                },
                Evals {
                    domain: d2,
                    evals: es2,
                },
            ) => {
                assert_eq!(d1, d2);
                es1 += &es2;
                Evals {
                    domain: d1,
                    evals: es1,
                }
            }
            (
                SubEvals {
                    domain: d_sub,
                    shift: s,
                    evals: es_sub,
                },
                Evals {
                    domain: d,
                    mut evals,
                },
            )
            | (
                Evals {
                    domain: d,
                    mut evals,
                },
                SubEvals {
                    domain: d_sub,
                    shift: s,
                    evals: es_sub,
                },
            ) => {
                let scale = (d_sub as usize) / (d as usize);
                assert!(
                    scale != 0,
                    "Check that the implementation of
                column_domain and the evaluation domain of the
                witnesses are the same"
                );
                evals.evals.par_iter_mut().enumerate().for_each(|(i, e)| {
                    *e += es_sub.evals[(scale * i + (d_sub as usize) * s) % es_sub.evals.len()];
                });
                Evals { evals, domain: d }
            }
            (
                SubEvals {
                    domain: d1,
                    shift: s1,
                    evals: es1,
                },
                SubEvals {
                    domain: d2,
                    shift: s2,
                    evals: es2,
                },
            ) => {
                let scale1 = (d1 as usize) / (res_domain.0 as usize);
                assert!(
                    scale1 != 0,
                    "Check that the implementation of
                column_domain and the evaluation domain of the
                witnesses are the same"
                );
                let scale2 = (d2 as usize) / (res_domain.0 as usize);
                assert!(
                    scale2 != 0,
                    "Check that the implementation of
                column_domain and the evaluation domain of the
                witnesses are the same"
                );
                let n = res_domain.1.size();
                let v: Vec<_> = (0..n)
                    .into_par_iter()
                    .map(|i| {
                        es1.evals[(scale1 * i + (d1 as usize) * s1) % es1.evals.len()]
                            + es2.evals[(scale2 * i + (d2 as usize) * s2) % es2.evals.len()]
                    })
                    .collect();

                Evals {
                    domain: res_domain.0,
                    evals: Evaluations::<F, D<F>>::from_vec_and_domain(v, res_domain.1),
                }
            }
        }
    }

    fn sub<'c>(self, other: EvalResult<'_, F>, res_domain: (Domain, D<F>)) -> EvalResult<'c, F> {
        use EvalResult::*;
        match (self, other) {
            (Constant(x), Constant(y)) => Constant(x - y),
            (Evals { domain, mut evals }, Constant(x)) => {
                evals.evals.par_iter_mut().for_each(|e| *e -= x);
                Evals { domain, evals }
            }
            (Constant(x), Evals { domain, mut evals }) => {
                evals.evals.par_iter_mut().for_each(|e| *e = x - *e);
                Evals { domain, evals }
            }
            (
                SubEvals {
                    evals,
                    domain: d,
                    shift: s,
                },
                Constant(x),
            ) => {
                let scale = (d as usize) / (res_domain.0 as usize);
                assert!(
                    scale != 0,
                    "Check that the implementation of
                column_domain and the evaluation domain of the
                witnesses are the same"
                );
                EvalResult::init(res_domain, |i| {
                    evals.evals[(scale * i + (d as usize) * s) % evals.evals.len()] - x
                })
            }
            (
                Constant(x),
                SubEvals {
                    evals,
                    domain: d,
                    shift: s,
                },
            ) => {
                let scale = (d as usize) / (res_domain.0 as usize);
                assert!(
                    scale != 0,
                    "Check that the implementation of
                column_domain and the evaluation domain of the
                witnesses are the same"
                );

                EvalResult::init(res_domain, |i| {
                    x - evals.evals[(scale * i + (d as usize) * s) % evals.evals.len()]
                })
            }
            (
                Evals {
                    domain: d1,
                    evals: mut es1,
                },
                Evals {
                    domain: d2,
                    evals: es2,
                },
            ) => {
                assert_eq!(d1, d2);
                es1 -= &es2;
                Evals {
                    domain: d1,
                    evals: es1,
                }
            }
            (
                SubEvals {
                    domain: d_sub,
                    shift: s,
                    evals: es_sub,
                },
                Evals {
                    domain: d,
                    mut evals,
                },
            ) => {
                let scale = (d_sub as usize) / (d as usize);
                assert!(
                    scale != 0,
                    "Check that the implementation of
                column_domain and the evaluation domain of the
                witnesses are the same"
                );

                evals.evals.par_iter_mut().enumerate().for_each(|(i, e)| {
                    *e = es_sub.evals[(scale * i + (d_sub as usize) * s) % es_sub.evals.len()] - *e;
                });
                Evals { evals, domain: d }
            }
            (
                Evals {
                    domain: d,
                    mut evals,
                },
                SubEvals {
                    domain: d_sub,
                    shift: s,
                    evals: es_sub,
                },
            ) => {
                let scale = (d_sub as usize) / (d as usize);
                assert!(
                    scale != 0,
                    "Check that the implementation of
                column_domain and the evaluation domain of the
                witnesses are the same"
                );
                evals.evals.par_iter_mut().enumerate().for_each(|(i, e)| {
                    *e -= es_sub.evals[(scale * i + (d_sub as usize) * s) % es_sub.evals.len()];
                });
                Evals { evals, domain: d }
            }
            (
                SubEvals {
                    domain: d1,
                    shift: s1,
                    evals: es1,
                },
                SubEvals {
                    domain: d2,
                    shift: s2,
                    evals: es2,
                },
            ) => {
                let scale1 = (d1 as usize) / (res_domain.0 as usize);
                assert!(
                    scale1 != 0,
                    "Check that the implementation of
                column_domain and the evaluation domain of the
                witnesses are the same"
                );
                let scale2 = (d2 as usize) / (res_domain.0 as usize);
                assert!(
                    scale2 != 0,
                    "Check that the implementation of
                column_domain and the evaluation domain of the
                witnesses are the same"
                );

                EvalResult::init(res_domain, |i| {
                    es1.evals[(scale1 * i + (d1 as usize) * s1) % es1.evals.len()]
                        - es2.evals[(scale2 * i + (d2 as usize) * s2) % es2.evals.len()]
                })
            }
        }
    }

    fn pow<'b>(self, d: u64, res_domain: (Domain, D<F>)) -> EvalResult<'b, F> {
        let mut acc = EvalResult::Constant(F::one());
        for i in (0..u64::BITS).rev() {
            acc = acc.square(res_domain);

            if (d >> i) & 1 == 1 {
                // TODO: Avoid the unnecessary cloning
                acc = acc.mul(self.clone(), res_domain)
            }
        }
        acc
    }

    fn square<'b>(self, res_domain: (Domain, D<F>)) -> EvalResult<'b, F> {
        use EvalResult::*;
        match self {
            Constant(x) => Constant(x.square()),
            Evals { domain, mut evals } => {
                evals.evals.par_iter_mut().for_each(|e| {
                    e.square_in_place();
                });
                Evals { domain, evals }
            }
            SubEvals {
                evals,
                domain: d,
                shift: s,
            } => {
                let scale = (d as usize) / (res_domain.0 as usize);
                assert!(
                    scale != 0,
                    "Check that the implementation of
                column_domain and the evaluation domain of the
                witnesses are the same"
                );
                EvalResult::init(res_domain, |i| {
                    evals.evals[(scale * i + (d as usize) * s) % evals.evals.len()].square()
                })
            }
        }
    }

    fn mul<'c>(self, other: EvalResult<'_, F>, res_domain: (Domain, D<F>)) -> EvalResult<'c, F> {
        use EvalResult::*;
        match (self, other) {
            (Constant(x), Constant(y)) => Constant(x * y),
            (Evals { domain, mut evals }, Constant(x))
            | (Constant(x), Evals { domain, mut evals }) => {
                evals.evals.par_iter_mut().for_each(|e| *e *= x);
                Evals { domain, evals }
            }
            (
                SubEvals {
                    evals,
                    domain: d,
                    shift: s,
                },
                Constant(x),
            )
            | (
                Constant(x),
                SubEvals {
                    evals,
                    domain: d,
                    shift: s,
                },
            ) => {
                let scale = (d as usize) / (res_domain.0 as usize);
                assert!(
                    scale != 0,
                    "Check that the implementation of
                column_domain and the evaluation domain of the
                witnesses are the same"
                );
                EvalResult::init(res_domain, |i| {
                    x * evals.evals[(scale * i + (d as usize) * s) % evals.evals.len()]
                })
            }
            (
                Evals {
                    domain: d1,
                    evals: mut es1,
                },
                Evals {
                    domain: d2,
                    evals: es2,
                },
            ) => {
                assert_eq!(d1, d2);
                es1 *= &es2;
                Evals {
                    domain: d1,
                    evals: es1,
                }
            }
            (
                SubEvals {
                    domain: d_sub,
                    shift: s,
                    evals: es_sub,
                },
                Evals {
                    domain: d,
                    mut evals,
                },
            )
            | (
                Evals {
                    domain: d,
                    mut evals,
                },
                SubEvals {
                    domain: d_sub,
                    shift: s,
                    evals: es_sub,
                },
            ) => {
                let scale = (d_sub as usize) / (d as usize);
                assert!(
                    scale != 0,
                    "Check that the implementation of
                column_domainand the evaluation domain of the
                witnesses are the same"
                );

                evals.evals.par_iter_mut().enumerate().for_each(|(i, e)| {
                    *e *= es_sub.evals[(scale * i + (d_sub as usize) * s) % es_sub.evals.len()];
                });
                Evals { evals, domain: d }
            }
            (
                SubEvals {
                    domain: d1,
                    shift: s1,
                    evals: es1,
                },
                SubEvals {
                    domain: d2,
                    shift: s2,
                    evals: es2,
                },
            ) => {
                let scale1 = (d1 as usize) / (res_domain.0 as usize);
                assert!(
                    scale1 != 0,
                    "Check that the implementation of
                column_domain and the evaluation domain of the
                witnesses are the same"
                );
                let scale2 = (d2 as usize) / (res_domain.0 as usize);

                assert!(
                    scale2 != 0,
                    "Check that the implementation of
                column_domain and the evaluation domain of the
                witnesses are the same"
                );
                EvalResult::init(res_domain, |i| {
                    es1.evals[(scale1 * i + (d1 as usize) * s1) % es1.evals.len()]
                        * es2.evals[(scale2 * i + (d2 as usize) * s2) % es2.evals.len()]
                })
            }
        }
    }
}

impl<'a, F: Field, Column: PartialEq + Copy, ChallengeTerm: AlphaChallengeTerm<'a>>
    Expr<ConstantExpr<F, ChallengeTerm>, Column>
{
    /// Convenience function for constructing expressions from literal
    /// field elements.
    pub fn literal(x: F) -> Self {
        ConstantTerm::Literal(x).into()
    }

    /// Combines multiple constraints `[c0, ..., cn]` into a single constraint
    /// `alpha^alpha0 * c0 + alpha^{alpha0 + 1} * c1 + ... + alpha^{alpha0 + n} * cn`.
    pub fn combine_constraints(alphas: impl Iterator<Item = u32>, cs: Vec<Self>) -> Self {
        let zero = Expr::<ConstantExpr<F, ChallengeTerm>, Column>::zero();
        cs.into_iter()
            .zip_eq(alphas)
            .map(|(c, i)| Expr::from(ConstantExpr::pow(ChallengeTerm::ALPHA.into(), i as u64)) * c)
            .fold(zero, |acc, x| acc + x)
    }
}

impl<F: FftField, Column: Copy, ChallengeTerm: Copy> Expr<ConstantExpr<F, ChallengeTerm>, Column> {
    /// Compile an expression to an RPN expression.
    pub fn to_polish(&self) -> Vec<PolishToken<F, Column, ChallengeTerm>> {
        let mut res = vec![];
        let mut cache = HashMap::new();
        self.to_polish_(&mut cache, &mut res);
        res
    }

    fn to_polish_(
        &self,
        cache: &mut HashMap<CacheId, usize>,
        res: &mut Vec<PolishToken<F, Column, ChallengeTerm>>,
    ) {
        match self {
            Expr::Double(x) => {
                x.to_polish_(cache, res);
                res.push(PolishToken::Dup);
                res.push(PolishToken::Add);
            }
            Expr::Square(x) => {
                x.to_polish_(cache, res);
                res.push(PolishToken::Dup);
                res.push(PolishToken::Mul);
            }
            Expr::Pow(x, d) => {
                x.to_polish_(cache, res);
                res.push(PolishToken::Pow(*d))
            }
            Expr::Atom(ExprInner::Constant(c)) => {
                c.to_polish(cache, res);
            }
            Expr::Atom(ExprInner::Cell(v)) => res.push(PolishToken::Cell(*v)),
            Expr::Atom(ExprInner::VanishesOnZeroKnowledgeAndPreviousRows) => {
                res.push(PolishToken::VanishesOnZeroKnowledgeAndPreviousRows);
            }
            Expr::Atom(ExprInner::UnnormalizedLagrangeBasis(i)) => {
                res.push(PolishToken::UnnormalizedLagrangeBasis(*i));
            }
            Expr::Add(x, y) => {
                x.to_polish_(cache, res);
                y.to_polish_(cache, res);
                res.push(PolishToken::Add);
            }
            Expr::Sub(x, y) => {
                x.to_polish_(cache, res);
                y.to_polish_(cache, res);
                res.push(PolishToken::Sub);
            }
            Expr::Mul(x, y) => {
                x.to_polish_(cache, res);
                y.to_polish_(cache, res);
                res.push(PolishToken::Mul);
            }
            Expr::Cache(id, e) => {
                match cache.get(id) {
                    Some(pos) =>
                    // Already computed and stored this.
                    {
                        res.push(PolishToken::Load(*pos))
                    }
                    None => {
                        // Haven't computed this yet. Compute it, then store it.
                        e.to_polish_(cache, res);
                        res.push(PolishToken::Store);
                        cache.insert(*id, cache.len());
                    }
                }
            }
            Expr::IfFeature(feature, e1, e2) => {
                {
                    // True branch
                    let tok = PolishToken::SkipIfNot(*feature, 0);
                    res.push(tok);
                    let len_before = res.len();
                    /* Clone the cache, to make sure we don't try to access cached statements later
                    when the feature flag is off. */
                    let mut cache = cache.clone();
                    e1.to_polish_(&mut cache, res);
                    let len_after = res.len();
                    res[len_before - 1] = PolishToken::SkipIfNot(*feature, len_after - len_before);
                }

                {
                    // False branch
                    let tok = PolishToken::SkipIfNot(*feature, 0);
                    res.push(tok);
                    let len_before = res.len();
                    /* Clone the cache, to make sure we don't try to access cached statements later
                    when the feature flag is on. */
                    let mut cache = cache.clone();
                    e2.to_polish_(&mut cache, res);
                    let len_after = res.len();
                    res[len_before - 1] = PolishToken::SkipIfNot(*feature, len_after - len_before);
                }
            }
        }
    }
}

impl<F: FftField, Column: PartialEq + Copy, ChallengeTerm: Copy>
    Expr<ConstantExpr<F, ChallengeTerm>, Column>
{
    fn evaluate_constants_(
        &self,
        c: &Constants<F>,
        chals: &dyn Index<ChallengeTerm, Output = F>,
    ) -> Expr<F, Column> {
        use ExprInner::*;
        use Operations::*;
        // TODO: Use cache
        match self {
            Double(x) => x.evaluate_constants_(c, chals).double(),
            Pow(x, d) => x.evaluate_constants_(c, chals).pow(*d),
            Square(x) => x.evaluate_constants_(c, chals).square(),
            Atom(Constant(x)) => Atom(Constant(x.value(c, chals))),
            Atom(Cell(v)) => Atom(Cell(*v)),
            Atom(VanishesOnZeroKnowledgeAndPreviousRows) => {
                Atom(VanishesOnZeroKnowledgeAndPreviousRows)
            }
            Atom(UnnormalizedLagrangeBasis(i)) => Atom(UnnormalizedLagrangeBasis(*i)),
            Add(x, y) => x.evaluate_constants_(c, chals) + y.evaluate_constants_(c, chals),
            Mul(x, y) => x.evaluate_constants_(c, chals) * y.evaluate_constants_(c, chals),
            Sub(x, y) => x.evaluate_constants_(c, chals) - y.evaluate_constants_(c, chals),
            Cache(id, e) => Cache(*id, Box::new(e.evaluate_constants_(c, chals))),
            IfFeature(feature, e1, e2) => IfFeature(
                *feature,
                Box::new(e1.evaluate_constants_(c, chals)),
                Box::new(e2.evaluate_constants_(c, chals)),
            ),
        }
    }

    /// Evaluate an expression as a field element against an environment.
    pub fn evaluate<
        'a,
        Evaluations: ColumnEvaluations<F, Column = Column>,
        Challenge: Index<ChallengeTerm, Output = F>,
        Environment: ColumnEnvironment<'a, F, ChallengeTerm, Challenge, Column = Column>,
    >(
        &self,
        d: D<F>,
        pt: F,
        evals: &Evaluations,
        env: &Environment,
    ) -> Result<F, ExprError<Column>> {
        self.evaluate_(d, pt, evals, env.get_constants(), env.get_challenges())
    }

    /// Evaluate an expression as a field element against the constants.
    pub fn evaluate_<Evaluations: ColumnEvaluations<F, Column = Column>>(
        &self,
        d: D<F>,
        pt: F,
        evals: &Evaluations,
        c: &Constants<F>,
        chals: &dyn Index<ChallengeTerm, Output = F>,
    ) -> Result<F, ExprError<Column>> {
        use ExprInner::*;
        use Operations::*;
        match self {
            Double(x) => x.evaluate_(d, pt, evals, c, chals).map(|x| x.double()),
            Atom(Constant(x)) => Ok(x.value(c, chals)),
            Pow(x, p) => Ok(x.evaluate_(d, pt, evals, c, chals)?.pow([*p])),
            Mul(x, y) => {
                let x = (*x).evaluate_(d, pt, evals, c, chals)?;
                let y = (*y).evaluate_(d, pt, evals, c, chals)?;
                Ok(x * y)
            }
            Square(x) => Ok(x.evaluate_(d, pt, evals, c, chals)?.square()),
            Add(x, y) => {
                let x = (*x).evaluate_(d, pt, evals, c, chals)?;
                let y = (*y).evaluate_(d, pt, evals, c, chals)?;
                Ok(x + y)
            }
            Sub(x, y) => {
                let x = (*x).evaluate_(d, pt, evals, c, chals)?;
                let y = (*y).evaluate_(d, pt, evals, c, chals)?;
                Ok(x - y)
            }
            Atom(VanishesOnZeroKnowledgeAndPreviousRows) => {
                Ok(eval_vanishes_on_last_n_rows(d, c.zk_rows + 1, pt))
            }
            Atom(UnnormalizedLagrangeBasis(i)) => {
                let offset = if i.zk_rows {
                    -(c.zk_rows as i32) + i.offset
                } else {
                    i.offset
                };
                Ok(unnormalized_lagrange_basis(&d, offset, &pt))
            }
            Atom(Cell(v)) => v.evaluate(evals),
            Cache(_, e) => e.evaluate_(d, pt, evals, c, chals),
            IfFeature(feature, e1, e2) => {
                if feature.is_enabled() {
                    e1.evaluate_(d, pt, evals, c, chals)
                } else {
                    e2.evaluate_(d, pt, evals, c, chals)
                }
            }
        }
    }

    /// Evaluate the constant expressions in this expression down into field elements.
    pub fn evaluate_constants<
        'a,
        Challenge: Index<ChallengeTerm, Output = F>,
        Environment: ColumnEnvironment<'a, F, ChallengeTerm, Challenge, Column = Column>,
    >(
        &self,
        env: &Environment,
    ) -> Expr<F, Column> {
        self.evaluate_constants_(env.get_constants(), env.get_challenges())
    }

    /// Compute the polynomial corresponding to this expression, in evaluation form.
    /// The routine will first replace the constants (verifier challenges and
    /// constants like the matrix used by `Poseidon`) in the expression with their
    /// respective values using `evaluate_constants` and will after evaluate the
    /// monomials with the corresponding column values using the method
    /// `evaluations`.
    pub fn evaluations<
        'a,
        Challenge: Index<ChallengeTerm, Output = F>,
        Environment: ColumnEnvironment<'a, F, ChallengeTerm, Challenge, Column = Column>,
    >(
        &self,
        env: &Environment,
    ) -> Evaluations<F, D<F>> {
        self.evaluate_constants(env).evaluations(env)
    }
}

/// Use as a result of the expression evaluations routine.
/// For now, the left branch is the result of an evaluation and the right branch
/// is the ID of an element in the cache
enum Either<A, B> {
    Left(A),
    Right(B),
}

impl<F: FftField, Column: Copy> Expr<F, Column> {
    /// Evaluate an expression into a field element.
    pub fn evaluate<Evaluations: ColumnEvaluations<F, Column = Column>>(
        &self,
        d: D<F>,
        pt: F,
        zk_rows: u64,
        evals: &Evaluations,
    ) -> Result<F, ExprError<Column>> {
        use ExprInner::*;
        use Operations::*;
        match self {
            Atom(Constant(x)) => Ok(*x),
            Pow(x, p) => Ok(x.evaluate(d, pt, zk_rows, evals)?.pow([*p])),
            Double(x) => x.evaluate(d, pt, zk_rows, evals).map(|x| x.double()),
            Square(x) => x.evaluate(d, pt, zk_rows, evals).map(|x| x.square()),
            Mul(x, y) => {
                let x = (*x).evaluate(d, pt, zk_rows, evals)?;
                let y = (*y).evaluate(d, pt, zk_rows, evals)?;
                Ok(x * y)
            }
            Add(x, y) => {
                let x = (*x).evaluate(d, pt, zk_rows, evals)?;
                let y = (*y).evaluate(d, pt, zk_rows, evals)?;
                Ok(x + y)
            }
            Sub(x, y) => {
                let x = (*x).evaluate(d, pt, zk_rows, evals)?;
                let y = (*y).evaluate(d, pt, zk_rows, evals)?;
                Ok(x - y)
            }
            Atom(VanishesOnZeroKnowledgeAndPreviousRows) => {
                Ok(eval_vanishes_on_last_n_rows(d, zk_rows + 1, pt))
            }
            Atom(UnnormalizedLagrangeBasis(i)) => {
                let offset = if i.zk_rows {
                    -(zk_rows as i32) + i.offset
                } else {
                    i.offset
                };
                Ok(unnormalized_lagrange_basis(&d, offset, &pt))
            }
            Atom(Cell(v)) => v.evaluate(evals),
            Cache(_, e) => e.evaluate(d, pt, zk_rows, evals),
            IfFeature(feature, e1, e2) => {
                if feature.is_enabled() {
                    e1.evaluate(d, pt, zk_rows, evals)
                } else {
                    e2.evaluate(d, pt, zk_rows, evals)
                }
            }
        }
    }

    /// Compute the polynomial corresponding to this expression, in evaluation form.
    pub fn evaluations<
        'a,
        ChallengeTerm,
        Challenge: Index<ChallengeTerm, Output = F>,
        Environment: ColumnEnvironment<'a, F, ChallengeTerm, Challenge, Column = Column>,
    >(
        &self,
        env: &Environment,
    ) -> Evaluations<F, D<F>> {
        let d1_size = env.get_domain(Domain::D1).size;
        let deg = self.degree(d1_size, env.get_constants().zk_rows);
        let d = if deg <= d1_size {
            Domain::D1
        } else if deg <= 4 * d1_size {
            Domain::D4
        } else if deg <= 8 * d1_size {
            Domain::D8
        } else {
            panic!("constraint had degree {deg} > d8 ({})", 8 * d1_size);
        };

        let mut cache = HashMap::new();

        let evals = match self.evaluations_helper(&mut cache, d, env) {
            Either::Left(x) => x,
            Either::Right(id) => cache.get(&id).unwrap().clone(),
        };

        match evals {
            EvalResult::Evals { evals, domain } => {
                assert_eq!(domain, d);
                evals
            }
            EvalResult::Constant(x) => EvalResult::init_((d, env.get_domain(d)), |_| x),
            EvalResult::SubEvals {
                evals,
                domain: d_sub,
                shift: s,
            } => {
                let res_domain = env.get_domain(d);
                let scale = (d_sub as usize) / (d as usize);
                assert!(
                    scale != 0,
                    "Check that the implementation of
                column_domain and the evaluation domain of the
                witnesses are the same"
                );
                EvalResult::init_((d, res_domain), |i| {
                    evals.evals[(scale * i + (d_sub as usize) * s) % evals.evals.len()]
                })
            }
        }
    }

    fn evaluations_helper<
        'a,
        'b,
        ChallengeTerm,
        Challenge: Index<ChallengeTerm, Output = F>,
        Environment: ColumnEnvironment<'a, F, ChallengeTerm, Challenge, Column = Column>,
    >(
        &self,
        cache: &'b mut HashMap<CacheId, EvalResult<'a, F>>,
        d: Domain,
        env: &Environment,
    ) -> Either<EvalResult<'a, F>, CacheId>
    where
        'a: 'b,
    {
        let dom = (d, env.get_domain(d));

        let res: EvalResult<'a, F> = match self {
            Expr::Square(x) => match x.evaluations_helper(cache, d, env) {
                Either::Left(x) => x.square(dom),
                Either::Right(id) => id.get_from(cache).unwrap().square(dom),
            },
            Expr::Double(x) => {
                let x = x.evaluations_helper(cache, d, env);
                let res = match x {
                    Either::Left(x) => {
                        let x = match x {
                            EvalResult::Evals { domain, mut evals } => {
                                evals.evals.par_iter_mut().for_each(|x| {
                                    x.double_in_place();
                                });
                                return Either::Left(EvalResult::Evals { domain, evals });
                            }
                            x => x,
                        };
                        let xx = || match &x {
                            EvalResult::Constant(x) => EvalResult::Constant(*x),
                            EvalResult::SubEvals {
                                domain,
                                shift,
                                evals,
                            } => EvalResult::SubEvals {
                                domain: *domain,
                                shift: *shift,
                                evals,
                            },
                            EvalResult::Evals { domain, evals } => EvalResult::SubEvals {
                                domain: *domain,
                                shift: 0,
                                evals,
                            },
                        };
                        xx().add(xx(), dom)
                    }
                    Either::Right(id) => {
                        let x1 = id.get_from(cache).unwrap();
                        let x2 = id.get_from(cache).unwrap();
                        x1.add(x2, dom)
                    }
                };
                return Either::Left(res);
            }
            Expr::Cache(id, e) => match cache.get(id) {
                Some(_) => return Either::Right(*id),
                None => {
                    match e.evaluations_helper(cache, d, env) {
                        Either::Left(es) => {
                            cache.insert(*id, es);
                        }
                        Either::Right(_) => {}
                    };
                    return Either::Right(*id);
                }
            },
            Expr::Pow(x, p) => {
                let x = x.evaluations_helper(cache, d, env);
                match x {
                    Either::Left(x) => x.pow(*p, (d, env.get_domain(d))),
                    Either::Right(id) => {
                        id.get_from(cache).unwrap().pow(*p, (d, env.get_domain(d)))
                    }
                }
            }
            Expr::Atom(ExprInner::VanishesOnZeroKnowledgeAndPreviousRows) => EvalResult::SubEvals {
                domain: Domain::D8,
                shift: 0,
                evals: env.vanishes_on_zero_knowledge_and_previous_rows(),
            },
            Expr::Atom(ExprInner::Constant(x)) => EvalResult::Constant(*x),
            Expr::Atom(ExprInner::UnnormalizedLagrangeBasis(i)) => {
                let offset = if i.zk_rows {
                    -(env.get_constants().zk_rows as i32) + i.offset
                } else {
                    i.offset
                };
                EvalResult::Evals {
                    domain: d,
                    evals: unnormalized_lagrange_evals(env.l0_1(), offset, d, env),
                }
            }
            Expr::Atom(ExprInner::Cell(Variable { col, row })) => {
                let evals: &'a Evaluations<F, D<F>> = {
                    match env.get_column(col) {
                        None => return Either::Left(EvalResult::Constant(F::zero())),
                        Some(e) => e,
                    }
                };
                EvalResult::SubEvals {
                    domain: env.column_domain(col),
                    shift: row.shift(),
                    evals,
                }
            }
            Expr::Add(e1, e2) => {
                let dom = (d, env.get_domain(d));
                let f = |x: EvalResult<F>, y: EvalResult<F>| x.add(y, dom);
                let e1 = e1.evaluations_helper(cache, d, env);
                let e2 = e2.evaluations_helper(cache, d, env);
                use Either::*;
                match (e1, e2) {
                    (Left(e1), Left(e2)) => f(e1, e2),
                    (Right(id1), Left(e2)) => f(id1.get_from(cache).unwrap(), e2),
                    (Left(e1), Right(id2)) => f(e1, id2.get_from(cache).unwrap()),
                    (Right(id1), Right(id2)) => {
                        f(id1.get_from(cache).unwrap(), id2.get_from(cache).unwrap())
                    }
                }
            }
            Expr::Sub(e1, e2) => {
                let dom = (d, env.get_domain(d));
                let f = |x: EvalResult<F>, y: EvalResult<F>| x.sub(y, dom);
                let e1 = e1.evaluations_helper(cache, d, env);
                let e2 = e2.evaluations_helper(cache, d, env);
                use Either::*;
                match (e1, e2) {
                    (Left(e1), Left(e2)) => f(e1, e2),
                    (Right(id1), Left(e2)) => f(id1.get_from(cache).unwrap(), e2),
                    (Left(e1), Right(id2)) => f(e1, id2.get_from(cache).unwrap()),
                    (Right(id1), Right(id2)) => {
                        f(id1.get_from(cache).unwrap(), id2.get_from(cache).unwrap())
                    }
                }
            }
            Expr::Mul(e1, e2) => {
                let dom = (d, env.get_domain(d));
                let f = |x: EvalResult<F>, y: EvalResult<F>| x.mul(y, dom);
                let e1 = e1.evaluations_helper(cache, d, env);
                let e2 = e2.evaluations_helper(cache, d, env);
                use Either::*;
                match (e1, e2) {
                    (Left(e1), Left(e2)) => f(e1, e2),
                    (Right(id1), Left(e2)) => f(id1.get_from(cache).unwrap(), e2),
                    (Left(e1), Right(id2)) => f(e1, id2.get_from(cache).unwrap()),
                    (Right(id1), Right(id2)) => {
                        f(id1.get_from(cache).unwrap(), id2.get_from(cache).unwrap())
                    }
                }
            }
            Expr::IfFeature(feature, e1, e2) => {
                /* Clone the cache, to make sure we don't try to access cached statements later
                when the feature flag is off. */
                let mut cache = cache.clone();
                if feature.is_enabled() {
                    return e1.evaluations_helper(&mut cache, d, env);
                } else {
                    return e2.evaluations_helper(&mut cache, d, env);
                }
            }
        };
        Either::Left(res)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
/// A "linearization", which is linear combination with `E` coefficients of
/// columns.
pub struct Linearization<E, Column> {
    pub constant_term: E,
    pub index_terms: Vec<(Column, E)>,
}

impl<E: Default, Column> Default for Linearization<E, Column> {
    fn default() -> Self {
        Linearization {
            constant_term: E::default(),
            index_terms: vec![],
        }
    }
}

impl<A, Column: Copy> Linearization<A, Column> {
    /// Apply a function to all the coefficients in the linearization.
    pub fn map<B, F: Fn(&A) -> B>(&self, f: F) -> Linearization<B, Column> {
        Linearization {
            constant_term: f(&self.constant_term),
            index_terms: self.index_terms.iter().map(|(c, x)| (*c, f(x))).collect(),
        }
    }
}

impl<F: FftField, Column: PartialEq + Copy, ChallengeTerm: Copy>
    Linearization<Expr<ConstantExpr<F, ChallengeTerm>, Column>, Column>
{
    /// Evaluate the constants in a linearization with `ConstantExpr<F>` coefficients down
    /// to literal field elements.
    pub fn evaluate_constants<
        'a,
        Challenge: Index<ChallengeTerm, Output = F>,
        Environment: ColumnEnvironment<'a, F, ChallengeTerm, Challenge, Column = Column>,
    >(
        &self,
        env: &Environment,
    ) -> Linearization<Expr<F, Column>, Column> {
        self.map(|e| e.evaluate_constants(env))
    }
}

impl<F: FftField, Column: Copy + Debug, ChallengeTerm: Copy>
    Linearization<Vec<PolishToken<F, Column, ChallengeTerm>>, Column>
{
    /// Given a linearization and an environment, compute the polynomial corresponding to the
    /// linearization, in evaluation form.
    pub fn to_polynomial<
        'a,
        Challenge: Index<ChallengeTerm, Output = F>,
        ColEvaluations: ColumnEvaluations<F, Column = Column>,
        Environment: ColumnEnvironment<'a, F, ChallengeTerm, Challenge, Column = Column>,
    >(
        &self,
        env: &Environment,
        pt: F,
        evals: &ColEvaluations,
    ) -> (F, Evaluations<F, D<F>>) {
        let cs = env.get_constants();
        let chals = env.get_challenges();
        let d1 = env.get_domain(Domain::D1);
        let n = d1.size();
        let mut res = vec![F::zero(); n];
        self.index_terms.iter().for_each(|(idx, c)| {
            let c = PolishToken::evaluate(c, d1, pt, evals, cs, chals).unwrap();
            let e = env
                .get_column(idx)
                .unwrap_or_else(|| panic!("Index polynomial {idx:?} not found"));
            let scale = e.evals.len() / n;
            res.par_iter_mut()
                .enumerate()
                .for_each(|(i, r)| *r += c * e.evals[scale * i]);
        });
        let p = Evaluations::<F, D<F>>::from_vec_and_domain(res, d1);
        (
            PolishToken::evaluate(&self.constant_term, d1, pt, evals, cs, chals).unwrap(),
            p,
        )
    }
}

impl<F: FftField, Column: Debug + PartialEq + Copy, ChallengeTerm: Copy>
    Linearization<Expr<ConstantExpr<F, ChallengeTerm>, Column>, Column>
{
    /// Given a linearization and an environment, compute the polynomial corresponding to the
    /// linearization, in evaluation form.
    pub fn to_polynomial<
        'a,
        Challenge: Index<ChallengeTerm, Output = F>,
        ColEvaluations: ColumnEvaluations<F, Column = Column>,
        Environment: ColumnEnvironment<'a, F, ChallengeTerm, Challenge, Column = Column>,
    >(
        &self,
        env: &Environment,
        pt: F,
        evals: &ColEvaluations,
    ) -> (F, DensePolynomial<F>) {
        let cs = env.get_constants();
        let chals = env.get_challenges();
        let d1 = env.get_domain(Domain::D1);
        let n = d1.size();
        let mut res = vec![F::zero(); n];
        self.index_terms.iter().for_each(|(idx, c)| {
            let c = c.evaluate_(d1, pt, evals, cs, chals).unwrap();
            let e = env
                .get_column(idx)
                .unwrap_or_else(|| panic!("Index polynomial {idx:?} not found"));
            let scale = e.evals.len() / n;
            res.par_iter_mut()
                .enumerate()
                .for_each(|(i, r)| *r += c * e.evals[scale * i])
        });
        let p = Evaluations::<F, D<F>>::from_vec_and_domain(res, d1).interpolate();
        (
            self.constant_term
                .evaluate_(d1, pt, evals, cs, chals)
                .unwrap(),
            p,
        )
    }
}

type Monomials<F, Column> = HashMap<Vec<Variable<Column>>, Expr<F, Column>>;

fn mul_monomials<
    F: Neg<Output = F> + Clone + One + Zero + PartialEq,
    Column: Ord + Copy + core::hash::Hash,
>(
    e1: &Monomials<F, Column>,
    e2: &Monomials<F, Column>,
) -> Monomials<F, Column>
where
    ExprInner<F, Column>: Literal,
    <ExprInner<F, Column> as Literal>::F: Field,
{
    let mut res: HashMap<_, Expr<F, Column>> = HashMap::new();
    for (m1, c1) in e1.iter() {
        for (m2, c2) in e2.iter() {
            let mut m = m1.clone();
            m.extend(m2);
            m.sort();
            let c1c2 = c1.clone() * c2.clone();
            let v = res.entry(m).or_insert_with(Expr::<F, Column>::zero);
            *v = v.clone() + c1c2;
        }
    }
    res
}

impl<
        F: Neg<Output = F> + Clone + One + Zero + PartialEq,
        Column: Ord + Copy + core::hash::Hash,
    > Expr<F, Column>
where
    ExprInner<F, Column>: Literal,
    <ExprInner<F, Column> as Literal>::F: Field,
{
    // TODO: This function (which takes linear time)
    // is called repeatedly in monomials, yielding quadratic behavior for
    // that function. It's ok for now as we only call that function once on
    // a small input when producing the verification key.
    fn is_constant(&self, evaluated: &HashSet<Column>) -> bool {
        use ExprInner::*;
        use Operations::*;
        match self {
            Pow(x, _) => x.is_constant(evaluated),
            Square(x) => x.is_constant(evaluated),
            Atom(Constant(_)) => true,
            Atom(Cell(v)) => evaluated.contains(&v.col),
            Double(x) => x.is_constant(evaluated),
            Add(x, y) | Sub(x, y) | Mul(x, y) => {
                x.is_constant(evaluated) && y.is_constant(evaluated)
            }
            Atom(VanishesOnZeroKnowledgeAndPreviousRows) => true,
            Atom(UnnormalizedLagrangeBasis(_)) => true,
            Cache(_, x) => x.is_constant(evaluated),
            IfFeature(_, e1, e2) => e1.is_constant(evaluated) && e2.is_constant(evaluated),
        }
    }

    fn monomials(&self, ev: &HashSet<Column>) -> HashMap<Vec<Variable<Column>>, Expr<F, Column>> {
        let sing = |v: Vec<Variable<Column>>, c: Expr<F, Column>| {
            let mut h = HashMap::new();
            h.insert(v, c);
            h
        };
        let constant = |e: Expr<F, Column>| sing(vec![], e);
        use ExprInner::*;
        use Operations::*;

        if self.is_constant(ev) {
            return constant(self.clone());
        }

        match self {
            Pow(x, d) => {
                // Run the multiplication logic with square and multiply
                let mut acc = sing(vec![], Expr::<F, Column>::one());
                let mut acc_is_one = true;
                let x = x.monomials(ev);

                for i in (0..u64::BITS).rev() {
                    if !acc_is_one {
                        let acc2 = mul_monomials(&acc, &acc);
                        acc = acc2;
                    }

                    if (d >> i) & 1 == 1 {
                        let res = mul_monomials(&acc, &x);
                        acc = res;
                        acc_is_one = false;
                    }
                }
                acc
            }
            Double(e) => {
                HashMap::from_iter(e.monomials(ev).into_iter().map(|(m, c)| (m, c.double())))
            }
            Cache(_, e) => e.monomials(ev),
            Atom(UnnormalizedLagrangeBasis(i)) => constant(Atom(UnnormalizedLagrangeBasis(*i))),
            Atom(VanishesOnZeroKnowledgeAndPreviousRows) => {
                constant(Atom(VanishesOnZeroKnowledgeAndPreviousRows))
            }
            Atom(Constant(c)) => constant(Atom(Constant(c.clone()))),
            Atom(Cell(var)) => sing(vec![*var], Atom(Constant(F::one()))),
            Add(e1, e2) => {
                let mut res = e1.monomials(ev);
                for (m, c) in e2.monomials(ev) {
                    let v = match res.remove(&m) {
                        None => c,
                        Some(v) => v + c,
                    };
                    res.insert(m, v);
                }
                res
            }
            Sub(e1, e2) => {
                let mut res = e1.monomials(ev);
                for (m, c) in e2.monomials(ev) {
                    let v = match res.remove(&m) {
                        None => -c, // Expr::constant(F::one()) * c,
                        Some(v) => v - c,
                    };
                    res.insert(m, v);
                }
                res
            }
            Mul(e1, e2) => {
                let e1 = e1.monomials(ev);
                let e2 = e2.monomials(ev);
                mul_monomials(&e1, &e2)
            }
            Square(x) => {
                let x = x.monomials(ev);
                mul_monomials(&x, &x)
            }
            IfFeature(feature, e1, e2) => {
                let mut res = HashMap::new();
                let e1_monomials = e1.monomials(ev);
                let mut e2_monomials = e2.monomials(ev);
                for (m, c) in e1_monomials.into_iter() {
                    let else_branch = match e2_monomials.remove(&m) {
                        None => Expr::zero(),
                        Some(c) => c,
                    };
                    let expr = Expr::IfFeature(*feature, Box::new(c), Box::new(else_branch));
                    res.insert(m, expr);
                }
                for (m, c) in e2_monomials.into_iter() {
                    let expr = Expr::IfFeature(*feature, Box::new(Expr::zero()), Box::new(c));
                    res.insert(m, expr);
                }
                res
            }
        }
    }

    /// There is an optimization in PLONK called "linearization" in which a certain
    /// polynomial is expressed as a linear combination of other polynomials in order
    /// to reduce the number of evaluations needed in the IOP (by relying on the homomorphic
    /// property of the polynomial commitments used.)
    ///
    /// The function performs this "linearization", which we now describe in some detail.
    ///
    /// In mathematical language, an expression `e: Expr<F>`
    /// is an element of the polynomial ring `F[V]`, where `V` is a set of variables.
    ///
    /// Given a subset `V_0` of `V` (and letting `V_1 = V \setminus V_0`), there is a map
    /// `factor_{V_0}: F[V] -> (F[V_1])[V_0]`. That is, polynomials with `F` coefficients in the variables `V = V_0 \cup V_1`
    /// are the same thing as polynomials with `F[V_1]` coefficients in variables `V_0`.
    ///
    /// There is also a function
    /// `lin_or_err : (F[V_1])[V_0] -> Result<Vec<(V_0, F[V_1])>, &str>`
    ///
    /// which checks if the given input is in fact a degree 1 polynomial in the variables `V_0`
    /// (i.e., a linear combination of `V_0` elements with `F[V_1]` coefficients)
    /// returning this linear combination if so.
    ///
    /// Given an expression `e` and set of columns `C_0`, letting
    /// `V_0 = { Variable { col: c, row: r } | c in C_0, r in { Curr, Next } }`,
    /// this function computes `lin_or_err(factor_{V_0}(e))`, although it does not
    /// compute it in that way. Instead, it computes it by reducing the expression into
    /// a sum of monomials with `F` coefficients, and then factors the monomials.
    pub fn linearize(
        &self,
        evaluated: HashSet<Column>,
    ) -> Result<Linearization<Expr<F, Column>, Column>, ExprError<Column>> {
        let mut res: HashMap<Column, Expr<F, Column>> = HashMap::new();
        let mut constant_term: Expr<F, Column> = Self::zero();
        let monomials = self.monomials(&evaluated);

        for (m, c) in monomials {
            let (evaluated, mut unevaluated): (Vec<_>, _) =
                m.into_iter().partition(|v| evaluated.contains(&v.col));
            let c = evaluated
                .into_iter()
                .fold(c, |acc, v| acc * Expr::Atom(ExprInner::Cell(v)));
            if unevaluated.is_empty() {
                constant_term += c;
            } else if unevaluated.len() == 1 {
                let var = unevaluated.remove(0);
                match var.row {
                    Next => {
                        return Err(ExprError::MissingEvaluation(var.col, var.row));
                    }
                    Curr => {
                        let e = match res.remove(&var.col) {
                            Some(v) => v + c,
                            None => c,
                        };
                        res.insert(var.col, e);
                        // This code used to be
                        //
                        // let v = res.entry(var.col).or_insert(0.into());
                        // *v = v.clone() + c
                        //
                        // but calling clone made it extremely slow, so I replaced it
                        // with the above that moves v out of the map with .remove and
                        // into v + c.
                        //
                        // I'm not sure if there's a way to do it with the HashMap API
                        // without calling remove.
                    }
                }
            } else {
                return Err(ExprError::FailedLinearization(unevaluated));
            }
        }
        Ok(Linearization {
            constant_term,
            index_terms: res.into_iter().collect(),
        })
    }
}

// Trait implementations

impl<T: Literal> Zero for Operations<T>
where
    T::F: Field,
{
    fn zero() -> Self {
        Self::literal(T::F::zero())
    }

    fn is_zero(&self) -> bool {
        if let Some(x) = self.to_literal_ref() {
            x.is_zero()
        } else {
            false
        }
    }
}

impl<T: Literal + PartialEq> One for Operations<T>
where
    T::F: Field,
{
    fn one() -> Self {
        Self::literal(T::F::one())
    }

    fn is_one(&self) -> bool {
        if let Some(x) = self.to_literal_ref() {
            x.is_one()
        } else {
            false
        }
    }
}

impl<T: Literal> Neg for Operations<T>
where
    T::F: One + Neg<Output = T::F> + Copy,
{
    type Output = Self;

    fn neg(self) -> Self {
        match self.to_literal() {
            Ok(x) => Self::literal(x.neg()),
            Err(x) => Operations::Mul(Box::new(Self::literal(T::F::one().neg())), Box::new(x)),
        }
    }
}

impl<T: Literal> Add<Self> for Operations<T>
where
    T::F: Field,
{
    type Output = Self;
    fn add(self, other: Self) -> Self {
        if self.is_zero() {
            return other;
        }
        if other.is_zero() {
            return self;
        }
        let (x, y) = {
            match (self.to_literal(), other.to_literal()) {
                (Ok(x), Ok(y)) => return Self::literal(x + y),
                (Ok(x), Err(y)) => (Self::literal(x), y),
                (Err(x), Ok(y)) => (x, Self::literal(y)),
                (Err(x), Err(y)) => (x, y),
            }
        };
        Operations::Add(Box::new(x), Box::new(y))
    }
}

impl<T: Literal> Sub<Self> for Operations<T>
where
    T::F: Field,
{
    type Output = Self;
    fn sub(self, other: Self) -> Self {
        if other.is_zero() {
            return self;
        }
        let (x, y) = {
            match (self.to_literal(), other.to_literal()) {
                (Ok(x), Ok(y)) => return Self::literal(x - y),
                (Ok(x), Err(y)) => (Self::literal(x), y),
                (Err(x), Ok(y)) => (x, Self::literal(y)),
                (Err(x), Err(y)) => (x, y),
            }
        };
        Operations::Sub(Box::new(x), Box::new(y))
    }
}

impl<T: Literal + PartialEq> Mul<Self> for Operations<T>
where
    T::F: Field,
{
    type Output = Self;
    fn mul(self, other: Self) -> Self {
        if self.is_zero() || other.is_zero() {
            return Self::zero();
        }

        if self.is_one() {
            return other;
        }
        if other.is_one() {
            return self;
        }
        let (x, y) = {
            match (self.to_literal(), other.to_literal()) {
                (Ok(x), Ok(y)) => return Self::literal(x * y),
                (Ok(x), Err(y)) => (Self::literal(x), y),
                (Err(x), Ok(y)) => (x, Self::literal(y)),
                (Err(x), Err(y)) => (x, y),
            }
        };
        Operations::Mul(Box::new(x), Box::new(y))
    }
}

impl<F: Zero + Clone, Column: Clone> AddAssign<Expr<F, Column>> for Expr<F, Column>
where
    ExprInner<F, Column>: Literal,
    <ExprInner<F, Column> as Literal>::F: Field,
{
    fn add_assign(&mut self, other: Self) {
        if self.is_zero() {
            *self = other;
        } else if !other.is_zero() {
            *self = Expr::Add(Box::new(self.clone()), Box::new(other));
        }
    }
}

impl<F, Column> MulAssign<Expr<F, Column>> for Expr<F, Column>
where
    F: Zero + One + PartialEq + Clone,
    Column: PartialEq + Clone,
    ExprInner<F, Column>: Literal,
    <ExprInner<F, Column> as Literal>::F: Field,
{
    fn mul_assign(&mut self, other: Self) {
        if self.is_zero() || other.is_zero() {
            *self = Self::zero();
        } else if self.is_one() {
            *self = other;
        } else if !other.is_one() {
            *self = Expr::Mul(Box::new(self.clone()), Box::new(other));
        }
    }
}

impl<F: Field, Column> From<u64> for Expr<F, Column> {
    fn from(x: u64) -> Self {
        Expr::Atom(ExprInner::Constant(F::from(x)))
    }
}

impl<'a, F: Field, Column, ChallengeTerm: AlphaChallengeTerm<'a>> From<u64>
    for Expr<ConstantExpr<F, ChallengeTerm>, Column>
{
    fn from(x: u64) -> Self {
        ConstantTerm::Literal(F::from(x)).into()
    }
}

impl<F: Field, ChallengeTerm> From<u64> for ConstantExpr<F, ChallengeTerm> {
    fn from(x: u64) -> Self {
        ConstantTerm::Literal(F::from(x)).into()
    }
}

impl<'a, F: Field, Column: PartialEq + Copy, ChallengeTerm: AlphaChallengeTerm<'a>> Mul<F>
    for Expr<ConstantExpr<F, ChallengeTerm>, Column>
{
    type Output = Expr<ConstantExpr<F, ChallengeTerm>, Column>;

    fn mul(self, y: F) -> Self::Output {
        Expr::from(ConstantTerm::Literal(y)) * self
    }
}

//
// Display
//

pub trait FormattedOutput: Sized {
    fn is_alpha(&self) -> bool;
    fn ocaml(&self, cache: &mut HashMap<CacheId, Self>) -> String;
    fn latex(&self, cache: &mut HashMap<CacheId, Self>) -> String;
    fn text(&self, cache: &mut HashMap<CacheId, Self>) -> String;
}

impl<'a, ChallengeTerm> FormattedOutput for ChallengeTerm
where
    ChallengeTerm: AlphaChallengeTerm<'a>,
{
    fn is_alpha(&self) -> bool {
        self.eq(&ChallengeTerm::ALPHA)
    }
    fn ocaml(&self, _cache: &mut HashMap<CacheId, Self>) -> String {
        self.to_string()
    }

    fn latex(&self, _cache: &mut HashMap<CacheId, Self>) -> String {
        "\\".to_string() + &self.to_string()
    }

    fn text(&self, _cache: &mut HashMap<CacheId, Self>) -> String {
        self.to_string()
    }
}

impl<F: PrimeField> FormattedOutput for ConstantTerm<F> {
    fn is_alpha(&self) -> bool {
        false
    }
    fn ocaml(&self, _cache: &mut HashMap<CacheId, Self>) -> String {
        use ConstantTerm::*;
        match self {
            EndoCoefficient => "endo_coefficient".to_string(),
            Mds { row, col } => format!("mds({row}, {col})"),
            Literal(x) => format!(
                "field(\"{:#066X}\")",
                Into::<num_bigint::BigUint>::into(x.into_bigint())
            ),
        }
    }

    fn latex(&self, _cache: &mut HashMap<CacheId, Self>) -> String {
        use ConstantTerm::*;
        match self {
            EndoCoefficient => "endo\\_coefficient".to_string(),
            Mds { row, col } => format!("mds({row}, {col})"),
            Literal(x) => format!("\\mathbb{{F}}({})", x.into_bigint().into()),
        }
    }

    fn text(&self, _cache: &mut HashMap<CacheId, Self>) -> String {
        use ConstantTerm::*;
        match self {
            EndoCoefficient => "endo_coefficient".to_string(),
            Mds { row, col } => format!("mds({row}, {col})"),
            Literal(x) => format!("0x{}", x.to_hex()),
        }
    }
}

impl<'a, F: PrimeField, ChallengeTerm> FormattedOutput for ConstantExprInner<F, ChallengeTerm>
where
    ChallengeTerm: AlphaChallengeTerm<'a>,
{
    fn is_alpha(&self) -> bool {
        use ConstantExprInner::*;
        match self {
            Challenge(x) => x.is_alpha(),
            Constant(x) => x.is_alpha(),
        }
    }
    fn ocaml(&self, cache: &mut HashMap<CacheId, Self>) -> String {
        use ConstantExprInner::*;
        match self {
            Challenge(x) => {
                let mut inner_cache = HashMap::new();
                let res = x.ocaml(&mut inner_cache);
                inner_cache.into_iter().for_each(|(k, v)| {
                    let _ = cache.insert(k, Challenge(v));
                });
                res
            }
            Constant(x) => {
                let mut inner_cache = HashMap::new();
                let res = x.ocaml(&mut inner_cache);
                inner_cache.into_iter().for_each(|(k, v)| {
                    let _ = cache.insert(k, Constant(v));
                });
                res
            }
        }
    }
    fn latex(&self, cache: &mut HashMap<CacheId, Self>) -> String {
        use ConstantExprInner::*;
        match self {
            Challenge(x) => {
                let mut inner_cache = HashMap::new();
                let res = x.latex(&mut inner_cache);
                inner_cache.into_iter().for_each(|(k, v)| {
                    let _ = cache.insert(k, Challenge(v));
                });
                res
            }
            Constant(x) => {
                let mut inner_cache = HashMap::new();
                let res = x.latex(&mut inner_cache);
                inner_cache.into_iter().for_each(|(k, v)| {
                    let _ = cache.insert(k, Constant(v));
                });
                res
            }
        }
    }
    fn text(&self, cache: &mut HashMap<CacheId, Self>) -> String {
        use ConstantExprInner::*;
        match self {
            Challenge(x) => {
                let mut inner_cache = HashMap::new();
                let res = x.text(&mut inner_cache);
                inner_cache.into_iter().for_each(|(k, v)| {
                    let _ = cache.insert(k, Challenge(v));
                });
                res
            }
            Constant(x) => {
                let mut inner_cache = HashMap::new();
                let res = x.text(&mut inner_cache);
                inner_cache.into_iter().for_each(|(k, v)| {
                    let _ = cache.insert(k, Constant(v));
                });
                res
            }
        }
    }
}

impl<Column: FormattedOutput + Debug> FormattedOutput for Variable<Column> {
    fn is_alpha(&self) -> bool {
        false
    }

    fn ocaml(&self, _cache: &mut HashMap<CacheId, Self>) -> String {
        format!("var({:?}, {:?})", self.col, self.row)
    }

    fn latex(&self, _cache: &mut HashMap<CacheId, Self>) -> String {
        let col = self.col.latex(&mut HashMap::new());
        match self.row {
            Curr => col,
            Next => format!("\\tilde{{{col}}}"),
        }
    }

    fn text(&self, _cache: &mut HashMap<CacheId, Self>) -> String {
        let col = self.col.text(&mut HashMap::new());
        match self.row {
            Curr => format!("Curr({col})"),
            Next => format!("Next({col})"),
        }
    }
}

impl<T: FormattedOutput + Clone> FormattedOutput for Operations<T> {
    fn is_alpha(&self) -> bool {
        match self {
            Operations::Atom(x) => x.is_alpha(),
            _ => false,
        }
    }
    fn ocaml(&self, cache: &mut HashMap<CacheId, Self>) -> String {
        use Operations::*;
        match self {
            Atom(x) => {
                let mut inner_cache = HashMap::new();
                let res = x.ocaml(&mut inner_cache);
                inner_cache.into_iter().for_each(|(k, v)| {
                    let _ = cache.insert(k, Atom(v));
                });
                res
            }
            Pow(x, n) => {
                if x.is_alpha() {
                    format!("alpha_pow({n})")
                } else {
                    format!("pow({}, {n})", x.ocaml(cache))
                }
            }
            Add(x, y) => format!("({} + {})", x.ocaml(cache), y.ocaml(cache)),
            Mul(x, y) => format!("({} * {})", x.ocaml(cache), y.ocaml(cache)),
            Sub(x, y) => format!("({} - {})", x.ocaml(cache), y.ocaml(cache)),
            Double(x) => format!("double({})", x.ocaml(cache)),
            Square(x) => format!("square({})", x.ocaml(cache)),
            Cache(id, e) => {
                cache.insert(*id, e.as_ref().clone());
                id.var_name()
            }
            IfFeature(feature, e1, e2) => {
                format!(
                    "if_feature({:?}, (fun () -> {}), (fun () -> {}))",
                    feature,
                    e1.ocaml(cache),
                    e2.ocaml(cache)
                )
            }
        }
    }

    fn latex(&self, cache: &mut HashMap<CacheId, Self>) -> String {
        use Operations::*;
        match self {
            Atom(x) => {
                let mut inner_cache = HashMap::new();
                let res = x.latex(&mut inner_cache);
                inner_cache.into_iter().for_each(|(k, v)| {
                    let _ = cache.insert(k, Atom(v));
                });
                res
            }
            Pow(x, n) => format!("{}^{{{n}}}", x.latex(cache)),
            Add(x, y) => format!("({} + {})", x.latex(cache), y.latex(cache)),
            Mul(x, y) => format!("({} \\cdot {})", x.latex(cache), y.latex(cache)),
            Sub(x, y) => format!("({} - {})", x.latex(cache), y.latex(cache)),
            Double(x) => format!("2 ({})", x.latex(cache)),
            Square(x) => format!("({})^2", x.latex(cache)),
            Cache(id, e) => {
                cache.insert(*id, e.as_ref().clone());
                id.var_name()
            }
            IfFeature(feature, _, _) => format!("{feature:?}"),
        }
    }

    fn text(&self, cache: &mut HashMap<CacheId, Self>) -> String {
        use Operations::*;
        match self {
            Atom(x) => {
                let mut inner_cache = HashMap::new();
                let res = x.text(&mut inner_cache);
                inner_cache.into_iter().for_each(|(k, v)| {
                    let _ = cache.insert(k, Atom(v));
                });
                res
            }
            Pow(x, n) => format!("{}^{n}", x.text(cache)),
            Add(x, y) => format!("({} + {})", x.text(cache), y.text(cache)),
            Mul(x, y) => format!("({} * {})", x.text(cache), y.text(cache)),
            Sub(x, y) => format!("({} - {})", x.text(cache), y.text(cache)),
            Double(x) => format!("double({})", x.text(cache)),
            Square(x) => format!("square({})", x.text(cache)),
            Cache(id, e) => {
                cache.insert(*id, e.as_ref().clone());
                id.var_name()
            }
            IfFeature(feature, _, _) => format!("{feature:?}"),
        }
    }
}

impl<'a, F, Column: FormattedOutput + Debug + Clone, ChallengeTerm> FormattedOutput
    for Expr<ConstantExpr<F, ChallengeTerm>, Column>
where
    F: PrimeField,
    ChallengeTerm: AlphaChallengeTerm<'a>,
{
    fn is_alpha(&self) -> bool {
        use ExprInner::*;
        use Operations::*;
        match self {
            Atom(Constant(x)) => x.is_alpha(),
            _ => false,
        }
    }
    /// Converts the expression in OCaml code
    /// Recursively print the expression,
    /// except for the cached expression that are stored in the `cache`.
    fn ocaml(
        &self,
        cache: &mut HashMap<CacheId, Expr<ConstantExpr<F, ChallengeTerm>, Column>>,
    ) -> String {
        use ExprInner::*;
        use Operations::*;
        match self {
            Double(x) => format!("double({})", x.ocaml(cache)),
            Atom(Constant(x)) => {
                let mut inner_cache = HashMap::new();
                let res = x.ocaml(&mut inner_cache);
                inner_cache.into_iter().for_each(|(k, v)| {
                    let _ = cache.insert(k, Atom(Constant(v)));
                });
                res
            }
            Atom(Cell(v)) => format!("cell({})", v.ocaml(&mut HashMap::new())),
            Atom(UnnormalizedLagrangeBasis(i)) => {
                format!("unnormalized_lagrange_basis({}, {})", i.zk_rows, i.offset)
            }
            Atom(VanishesOnZeroKnowledgeAndPreviousRows) => {
                "vanishes_on_zero_knowledge_and_previous_rows".to_string()
            }
            Add(x, y) => format!("({} + {})", x.ocaml(cache), y.ocaml(cache)),
            Mul(x, y) => format!("({} * {})", x.ocaml(cache), y.ocaml(cache)),
            Sub(x, y) => format!("({} - {})", x.ocaml(cache), y.ocaml(cache)),
            Pow(x, d) => format!("pow({}, {d})", x.ocaml(cache)),
            Square(x) => format!("square({})", x.ocaml(cache)),
            Cache(id, e) => {
                cache.insert(*id, e.as_ref().clone());
                id.var_name()
            }
            IfFeature(feature, e1, e2) => {
                format!(
                    "if_feature({:?}, (fun () -> {}), (fun () -> {}))",
                    feature,
                    e1.ocaml(cache),
                    e2.ocaml(cache)
                )
            }
        }
    }

    fn latex(
        &self,
        cache: &mut HashMap<CacheId, Expr<ConstantExpr<F, ChallengeTerm>, Column>>,
    ) -> String {
        use ExprInner::*;
        use Operations::*;
        match self {
            Double(x) => format!("2 ({})", x.latex(cache)),
            Atom(Constant(x)) => {
                let mut inner_cache = HashMap::new();
                let res = x.latex(&mut inner_cache);
                inner_cache.into_iter().for_each(|(k, v)| {
                    let _ = cache.insert(k, Atom(Constant(v)));
                });
                res
            }
            Atom(Cell(v)) => v.latex(&mut HashMap::new()),
            Atom(UnnormalizedLagrangeBasis(RowOffset {
                zk_rows: true,
                offset: i,
            })) => {
                format!("unnormalized\\_lagrange\\_basis(zk\\_rows + {})", *i)
            }
            Atom(UnnormalizedLagrangeBasis(RowOffset {
                zk_rows: false,
                offset: i,
            })) => {
                format!("unnormalized\\_lagrange\\_basis({})", *i)
            }
            Atom(VanishesOnZeroKnowledgeAndPreviousRows) => {
                "vanishes\\_on\\_zero\\_knowledge\\_and\\_previous\\_row".to_string()
            }
            Add(x, y) => format!("({} + {})", x.latex(cache), y.latex(cache)),
            Mul(x, y) => format!("({} \\cdot {})", x.latex(cache), y.latex(cache)),
            Sub(x, y) => format!("({} - {})", x.latex(cache), y.latex(cache)),
            Pow(x, d) => format!("{}^{{{d}}}", x.latex(cache)),
            Square(x) => format!("({})^2", x.latex(cache)),
            Cache(id, e) => {
                cache.insert(*id, e.as_ref().clone());
                id.latex_name()
            }
            IfFeature(feature, _, _) => format!("{feature:?}"),
        }
    }

    /// Recursively print the expression,
    /// except for the cached expression that are stored in the `cache`.
    fn text(
        &self,
        cache: &mut HashMap<CacheId, Expr<ConstantExpr<F, ChallengeTerm>, Column>>,
    ) -> String {
        use ExprInner::*;
        use Operations::*;
        match self {
            Double(x) => format!("double({})", x.text(cache)),
            Atom(Constant(x)) => {
                let mut inner_cache = HashMap::new();
                let res = x.text(&mut inner_cache);
                inner_cache.into_iter().for_each(|(k, v)| {
                    let _ = cache.insert(k, Atom(Constant(v)));
                });
                res
            }
            Atom(Cell(v)) => v.text(&mut HashMap::new()),
            Atom(UnnormalizedLagrangeBasis(RowOffset {
                zk_rows: true,
                offset: i,
            })) => match i.cmp(&0) {
                Ordering::Greater => format!("unnormalized_lagrange_basis(zk_rows + {})", *i),
                Ordering::Equal => "unnormalized_lagrange_basis(zk_rows)".to_string(),
                Ordering::Less => format!("unnormalized_lagrange_basis(zk_rows - {})", (-*i)),
            },
            Atom(UnnormalizedLagrangeBasis(RowOffset {
                zk_rows: false,
                offset: i,
            })) => {
                format!("unnormalized_lagrange_basis({})", *i)
            }
            Atom(VanishesOnZeroKnowledgeAndPreviousRows) => {
                "vanishes_on_zero_knowledge_and_previous_rows".to_string()
            }
            Add(x, y) => format!("({} + {})", x.text(cache), y.text(cache)),
            Mul(x, y) => format!("({} * {})", x.text(cache), y.text(cache)),
            Sub(x, y) => format!("({} - {})", x.text(cache), y.text(cache)),
            Pow(x, d) => format!("pow({}, {d})", x.text(cache)),
            Square(x) => format!("square({})", x.text(cache)),
            Cache(id, e) => {
                cache.insert(*id, e.as_ref().clone());
                id.var_name()
            }
            IfFeature(feature, _, _) => format!("{feature:?}"),
        }
    }
}

impl<'a, F, Column: FormattedOutput + Debug + Clone, ChallengeTerm>
    Expr<ConstantExpr<F, ChallengeTerm>, Column>
where
    F: PrimeField,
    ChallengeTerm: AlphaChallengeTerm<'a>,
{
    /// Converts the expression in LaTeX
    // It is only used by visual tooling like kimchi-visu
    pub fn latex_str(&self) -> Vec<String> {
        let mut env = HashMap::new();
        let e = self.latex(&mut env);

        let mut env: Vec<_> = env.into_iter().collect();
        // HashMap deliberately uses an unstable order; here we sort to ensure
        // that the output is consistent when printing.
        env.sort_by(|(x, _), (y, _)| x.cmp(y));

        let mut res = vec![];
        for (k, v) in env {
            let mut rhs = v.latex_str();
            let last = rhs.pop().expect("returned an empty expression");
            res.push(format!("{} = {last}", k.latex_name()));
            res.extend(rhs);
        }
        res.push(e);
        res
    }

    /// Converts the expression in OCaml code
    pub fn ocaml_str(&self) -> String {
        let mut env = HashMap::new();
        let e = self.ocaml(&mut env);

        let mut env: Vec<_> = env.into_iter().collect();
        // HashMap deliberately uses an unstable order; here we sort to ensure
        // that the output is consistent when printing.
        env.sort_by(|(x, _), (y, _)| x.cmp(y));

        let mut res = String::new();
        for (k, v) in env {
            let rhs = v.ocaml_str();
            let cached = format!("let {} = {rhs} in ", k.var_name());
            res.push_str(&cached);
        }

        res.push_str(&e);
        res
    }
}

//
// Constraints
//

/// A number of useful constraints
pub mod constraints {
    use o1_utils::Two;

    use crate::circuits::argument::ArgumentData;
    use core::fmt;

    use super::*;
    use crate::circuits::berkeley_columns::{coeff, witness};

    /// This trait defines a common arithmetic operations interface
    /// that can be used by constraints.  It allows us to reuse
    /// constraint code for witness computation.
    pub trait ExprOps<F, ChallengeTerm>:
        Add<Output = Self>
        + Sub<Output = Self>
        + Neg<Output = Self>
        + Mul<Output = Self>
        + AddAssign<Self>
        + MulAssign<Self>
        + Clone
        + Zero
        + One
        + From<u64>
        + fmt::Debug
        + fmt::Display
    // Add more as necessary
    where
        Self: core::marker::Sized,
    {
        /// 2^pow
        fn two_pow(pow: u64) -> Self;

        /// 2^{LIMB_BITS}
        fn two_to_limb() -> Self;

        /// 2^{2 * LIMB_BITS}
        fn two_to_2limb() -> Self;

        /// 2^{3 * LIMB_BITS}
        fn two_to_3limb() -> Self;

        /// Double the value
        fn double(&self) -> Self;

        /// Compute the square of this value
        fn square(&self) -> Self;

        /// Raise the value to the given power
        fn pow(&self, p: u64) -> Self;

        /// Constrain to boolean
        fn boolean(&self) -> Self;

        /// Constrain to crumb (i.e. two bits)
        fn crumb(&self) -> Self;

        /// Create a literal
        fn literal(x: F) -> Self;

        // Witness variable
        fn witness(row: CurrOrNext, col: usize, env: Option<&ArgumentData<F>>) -> Self;

        /// Coefficient
        fn coeff(col: usize, env: Option<&ArgumentData<F>>) -> Self;

        /// Create a constant
        fn constant(expr: ConstantExpr<F, ChallengeTerm>, env: Option<&ArgumentData<F>>) -> Self;

        /// Cache item
        fn cache(&self, cache: &mut Cache) -> Self;
    }
    // TODO generalize with generic Column/challengeterm
    // We need to create a trait for berkeley_columns::Environment
    impl<F> ExprOps<F, BerkeleyChallengeTerm>
        for Expr<ConstantExpr<F, BerkeleyChallengeTerm>, berkeley_columns::Column>
    where
        F: PrimeField,
        // TODO remove
        Expr<ConstantExpr<F, BerkeleyChallengeTerm>, berkeley_columns::Column>: core::fmt::Display,
    {
        fn two_pow(pow: u64) -> Self {
            Expr::<ConstantExpr<F, BerkeleyChallengeTerm>, berkeley_columns::Column>::literal(
                <F as Two<F>>::two_pow(pow),
            )
        }

        fn two_to_limb() -> Self {
            Expr::<ConstantExpr<F, BerkeleyChallengeTerm>, berkeley_columns::Column>::literal(
                KimchiForeignElement::<F>::two_to_limb(),
            )
        }

        fn two_to_2limb() -> Self {
            Expr::<ConstantExpr<F, BerkeleyChallengeTerm>, berkeley_columns::Column>::literal(
                KimchiForeignElement::<F>::two_to_2limb(),
            )
        }

        fn two_to_3limb() -> Self {
            Expr::<ConstantExpr<F, BerkeleyChallengeTerm>, berkeley_columns::Column>::literal(
                KimchiForeignElement::<F>::two_to_3limb(),
            )
        }

        fn double(&self) -> Self {
            Expr::double(self.clone())
        }

        fn square(&self) -> Self {
            Expr::square(self.clone())
        }

        fn pow(&self, p: u64) -> Self {
            Expr::pow(self.clone(), p)
        }

        fn boolean(&self) -> Self {
            constraints::boolean(self)
        }

        fn crumb(&self) -> Self {
            constraints::crumb(self)
        }

        fn literal(x: F) -> Self {
            ConstantTerm::Literal(x).into()
        }

        fn witness(row: CurrOrNext, col: usize, _: Option<&ArgumentData<F>>) -> Self {
            witness(col, row)
        }

        fn coeff(col: usize, _: Option<&ArgumentData<F>>) -> Self {
            coeff(col)
        }

        fn constant(
            expr: ConstantExpr<F, BerkeleyChallengeTerm>,
            _: Option<&ArgumentData<F>>,
        ) -> Self {
            Expr::from(expr)
        }

        fn cache(&self, cache: &mut Cache) -> Self {
            Expr::Cache(cache.next_id(), Box::new(self.clone()))
        }
    }
    // TODO generalize with generic Column/challengeterm
    // We need to generalize argument.rs
    impl<F: Field> ExprOps<F, BerkeleyChallengeTerm> for F {
        fn two_pow(pow: u64) -> Self {
            <F as Two<F>>::two_pow(pow)
        }

        fn two_to_limb() -> Self {
            KimchiForeignElement::<F>::two_to_limb()
        }

        fn two_to_2limb() -> Self {
            KimchiForeignElement::<F>::two_to_2limb()
        }

        fn two_to_3limb() -> Self {
            KimchiForeignElement::<F>::two_to_3limb()
        }

        fn double(&self) -> Self {
            *self * F::from(2u64)
        }

        fn square(&self) -> Self {
            *self * *self
        }

        fn pow(&self, p: u64) -> Self {
            self.pow([p])
        }

        fn boolean(&self) -> Self {
            constraints::boolean(self)
        }

        fn crumb(&self) -> Self {
            constraints::crumb(self)
        }

        fn literal(x: F) -> Self {
            x
        }

        fn witness(row: CurrOrNext, col: usize, env: Option<&ArgumentData<F>>) -> Self {
            match env {
                Some(data) => data.witness[(row, col)],
                None => panic!("Missing witness"),
            }
        }

        fn coeff(col: usize, env: Option<&ArgumentData<F>>) -> Self {
            match env {
                Some(data) => data.coeffs[col],
                None => panic!("Missing coefficients"),
            }
        }

        fn constant(
            expr: ConstantExpr<F, BerkeleyChallengeTerm>,
            env: Option<&ArgumentData<F>>,
        ) -> Self {
            match env {
                Some(data) => expr.value(&data.constants, &data.challenges),
                None => panic!("Missing constants"),
            }
        }

        fn cache(&self, _: &mut Cache) -> Self {
            *self
        }
    }

    /// Creates a constraint to enforce that b is either 0 or 1.
    pub fn boolean<F: Field, ChallengeTerm, T: ExprOps<F, ChallengeTerm>>(b: &T) -> T {
        b.square() - b.clone()
    }

    /// Crumb constraint for 2-bit value x
    pub fn crumb<F: Field, ChallengeTerm, T: ExprOps<F, ChallengeTerm>>(x: &T) -> T {
        // Assert x \in [0,3] i.e. assert x*(x - 1)*(x - 2)*(x - 3) == 0
        x.clone()
            * (x.clone() - 1u64.into())
            * (x.clone() - 2u64.into())
            * (x.clone() - 3u64.into())
    }

    /// lo + mi * 2^{LIMB_BITS}
    pub fn compact_limb<F: Field, ChallengeTerm, T: ExprOps<F, ChallengeTerm>>(
        lo: &T,
        mi: &T,
    ) -> T {
        lo.clone() + mi.clone() * T::two_to_limb()
    }
}

/// Auto clone macro - Helps make constraints more readable
/// by eliminating requirement to .clone() all the time
#[macro_export]
macro_rules! auto_clone {
    ($var:ident, $expr:expr) => {
        let $var = $expr;
        let $var = || $var.clone();
    };
    ($var:ident) => {
        let $var = || $var.clone();
    };
}
#[macro_export]
macro_rules! auto_clone_array {
    ($var:ident, $expr:expr) => {
        let $var = $expr;
        let $var = |i: usize| $var[i].clone();
    };
    ($var:ident) => {
        let $var = |i: usize| $var[i].clone();
    };
}

pub use auto_clone;
pub use auto_clone_array;

/// You can import this module like `use kimchi::circuits::expr::prologue::*` to obtain a number of handy aliases and helpers
pub mod prologue {
    pub use super::{
        berkeley_columns::{coeff, constant, index, witness, witness_curr, witness_next, E},
        FeatureFlag,
    };
}
