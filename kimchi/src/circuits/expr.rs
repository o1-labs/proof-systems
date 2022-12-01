use crate::{
    circuits::{
        domains::EvaluationDomains,
        gate::{CurrOrNext, GateType},
        lookup::{index::LookupSelectors, lookups::LookupPattern},
        polynomials::permutation::eval_vanishes_on_last_4_rows,
        wires::COLUMNS,
    },
    proof::ProofEvaluations,
};
use ark_ff::{FftField, Field, One, PrimeField, Zero};
use ark_poly::{
    univariate::DensePolynomial, EvaluationDomain, Evaluations, Radix2EvaluationDomain as D,
};
use itertools::Itertools;
use num_bigint::BigUint;
use o1_utils::{FieldHelpers, ForeignElement};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::ops::{Add, AddAssign, Mul, Neg, Sub};
use std::{
    collections::{HashMap, HashSet},
    ops::MulAssign,
};
use std::{fmt, iter::FromIterator};
use thiserror::Error;
use CurrOrNext::{Curr, Next};

use self::constraints::ExprOps;

#[derive(Debug, Error)]
pub enum ExprError {
    #[error("Empty stack")]
    EmptyStack,

    #[error("Lookup should not have been used")]
    LookupShouldNotBeUsed,

    #[error("Linearization failed (needed {0:?} evaluated at the {1:?} row")]
    MissingEvaluation(Column, CurrOrNext),

    #[error("Cannot get index evaluation {0:?} (should have been linearized away)")]
    MissingIndexEvaluation(Column),

    #[error("Linearization failed")]
    FailedLinearization,

    #[error("runtime table not available")]
    MissingRuntime,
}

/// The collection of constants required to evaluate an `Expr`.
pub struct Constants<F: 'static> {
    /// The challenge alpha from the PLONK IOP.
    pub alpha: F,
    /// The challenge beta from the PLONK IOP.
    pub beta: F,
    /// The challenge gamma from the PLONK IOP.
    pub gamma: F,
    /// The challenge joint_combiner which is used to combine
    /// joint lookup tables.
    pub joint_combiner: Option<F>,
    /// The endomorphism coefficient
    pub endo_coefficient: F,
    /// The MDS matrix
    pub mds: &'static Vec<Vec<F>>,
    /// The modulus for foreign field operations
    pub foreign_field_modulus: Option<BigUint>,
}

/// The polynomials specific to the lookup argument.
///
/// All are evaluations over the D8 domain
pub struct LookupEnvironment<'a, F: FftField> {
    /// The sorted lookup table polynomials.
    pub sorted: &'a Vec<Evaluations<F, D<F>>>,
    /// The lookup aggregation polynomials.
    pub aggreg: &'a Evaluations<F, D<F>>,
    /// The lookup-type selector polynomials.
    pub selectors: &'a LookupSelectors<Evaluations<F, D<F>>>,
    /// The evaluations of the combined lookup table polynomial.
    pub table: &'a Evaluations<F, D<F>>,
    /// The evaluations of the optional runtime selector polynomial.
    pub runtime_selector: Option<&'a Evaluations<F, D<F>>>,
    /// The evaluations of the optional runtime table.
    pub runtime_table: Option<&'a Evaluations<F, D<F>>>,
}

/// The collection of polynomials (all in evaluation form) and constants
/// required to evaluate an expression as a polynomial.
///
/// All are evaluations.
pub struct Environment<'a, F: FftField> {
    /// The witness column polynomials
    pub witness: &'a [Evaluations<F, D<F>>; COLUMNS],
    /// The coefficient column polynomials
    pub coefficient: &'a [Evaluations<F, D<F>>; COLUMNS],
    /// The polynomial which vanishes on the last 4 elements of the domain.
    pub vanishes_on_last_4_rows: &'a Evaluations<F, D<F>>,
    /// The permutation aggregation polynomial.
    pub z: &'a Evaluations<F, D<F>>,
    /// The index selector polynomials.
    pub index: HashMap<GateType, &'a Evaluations<F, D<F>>>,
    /// The value `prod_{j != 1} (1 - omega^j)`, used for efficiently
    /// computing the evaluations of the unnormalized Lagrange basis polynomials.
    pub l0_1: F,
    /// Constant values required
    pub constants: Constants<F>,
    /// The domains used in the PLONK argument.
    pub domain: EvaluationDomains<F>,
    /// Lookup specific polynomials
    pub lookup: Option<LookupEnvironment<'a, F>>,
}

impl<'a, F: FftField> Environment<'a, F> {
    fn get_column(&self, col: &Column) -> Option<&'a Evaluations<F, D<F>>> {
        use Column::*;
        let lookup = self.lookup.as_ref();
        match col {
            Witness(i) => Some(&self.witness[*i]),
            Coefficient(i) => Some(&self.coefficient[*i]),
            Z => Some(self.z),
            LookupKindIndex(i) => lookup.and_then(|l| l.selectors[*i].as_ref()),
            LookupSorted(i) => lookup.map(|l| &l.sorted[*i]),
            LookupAggreg => lookup.map(|l| l.aggreg),
            LookupTable => lookup.map(|l| l.table),
            LookupRuntimeSelector => lookup.and_then(|l| l.runtime_selector),
            LookupRuntimeTable => lookup.and_then(|l| l.runtime_table),
            Index(t) => match self.index.get(t) {
                None => None,
                Some(e) => Some(e),
            },
        }
    }
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
fn unnormalized_lagrange_basis<F: FftField>(domain: &D<F>, i: i32, pt: &F) -> F {
    let omega_i = if i < 0 {
        domain.group_gen.pow(&[-i as u64]).inverse().unwrap()
    } else {
        domain.group_gen.pow(&[i as u64])
    };
    domain.evaluate_vanishing_polynomial(*pt) / (*pt - omega_i)
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
/// A type representing one of the polynomials involved in the PLONK IOP.
pub enum Column {
    Witness(usize),
    Z,
    LookupSorted(usize),
    LookupAggreg,
    LookupTable,
    LookupKindIndex(LookupPattern),
    LookupRuntimeSelector,
    LookupRuntimeTable,
    Index(GateType),
    Coefficient(usize),
}

impl Column {
    fn domain(&self) -> Domain {
        match self {
            Column::Index(GateType::Generic) => Domain::D4,
            Column::Index(GateType::CompleteAdd) => Domain::D4,
            _ => Domain::D8,
        }
    }

    fn latex(&self) -> String {
        match self {
            Column::Witness(i) => format!("w_{{{i}}}"),
            Column::Z => "Z".to_string(),
            Column::LookupSorted(i) => format!("s_{{{}}}", i),
            Column::LookupAggreg => "a".to_string(),
            Column::LookupTable => "t".to_string(),
            Column::LookupKindIndex(i) => format!("k_{{{:?}}}", i),
            Column::LookupRuntimeSelector => "rts".to_string(),
            Column::LookupRuntimeTable => "rt".to_string(),
            Column::Index(gate) => {
                format!("{:?}", gate)
            }
            Column::Coefficient(i) => format!("c_{{{}}}", i),
        }
    }

    fn text(&self) -> String {
        match self {
            Column::Witness(i) => format!("w[{i}]"),
            Column::Z => "Z".to_string(),
            Column::LookupSorted(i) => format!("s[{}]", i),
            Column::LookupAggreg => "a".to_string(),
            Column::LookupTable => "t".to_string(),
            Column::LookupKindIndex(i) => format!("k[{:?}]", i),
            Column::LookupRuntimeSelector => "rts".to_string(),
            Column::LookupRuntimeTable => "rt".to_string(),
            Column::Index(gate) => {
                format!("{:?}", gate)
            }
            Column::Coefficient(i) => format!("c[{}]", i),
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
/// A type representing a variable which can appear in a constraint. It specifies a column
/// and a relative position (Curr or Next)
pub struct Variable {
    /// The column of this variable
    pub col: Column,
    /// The row (Curr of Next) of this variable
    pub row: CurrOrNext,
}

impl Variable {
    fn ocaml(&self) -> String {
        format!("var({:?}, {:?})", self.col, self.row)
    }

    fn latex(&self) -> String {
        let col = self.col.latex();
        match self.row {
            Curr => col,
            Next => format!("\\tilde{{{col}}}"),
        }
    }

    fn text(&self) -> String {
        let col = self.col.text();
        match self.row {
            Curr => format!("Curr({col})"),
            Next => format!("Next({col})"),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
/// An arithmetic expression over
///
/// - the operations *, +, -, ^
/// - the constants `alpha`, `beta`, `gamma`, `joint_combiner`, and literal field elements.
pub enum ConstantExpr<F> {
    // TODO: Factor these out into an enum just for Alpha, Beta, Gamma, JointCombiner
    Alpha,
    Beta,
    Gamma,
    JointCombiner,
    // TODO: EndoCoefficient and Mds differ from the other 4 base constants in
    // that they are known at compile time. This should be extracted out into two
    // separate constant expression types.
    EndoCoefficient,
    Mds { row: usize, col: usize },
    ForeignFieldModulus(usize),
    Literal(F),
    Pow(Box<ConstantExpr<F>>, u64),
    // TODO: I think having separate Add, Sub, Mul constructors is faster than
    // having a BinOp constructor :(
    Add(Box<ConstantExpr<F>>, Box<ConstantExpr<F>>),
    Mul(Box<ConstantExpr<F>>, Box<ConstantExpr<F>>),
    Sub(Box<ConstantExpr<F>>, Box<ConstantExpr<F>>),
}

impl<F: Copy> ConstantExpr<F> {
    fn to_polish_(&self, res: &mut Vec<PolishToken<F>>) {
        match self {
            ConstantExpr::Alpha => res.push(PolishToken::Alpha),
            ConstantExpr::Beta => res.push(PolishToken::Beta),
            ConstantExpr::Gamma => res.push(PolishToken::Gamma),
            ConstantExpr::JointCombiner => res.push(PolishToken::JointCombiner),
            ConstantExpr::EndoCoefficient => res.push(PolishToken::EndoCoefficient),
            ConstantExpr::Mds { row, col } => res.push(PolishToken::Mds {
                row: *row,
                col: *col,
            }),
            ConstantExpr::ForeignFieldModulus(i) => res.push(PolishToken::ForeignFieldModulus(*i)),
            ConstantExpr::Add(x, y) => {
                x.as_ref().to_polish_(res);
                y.as_ref().to_polish_(res);
                res.push(PolishToken::Add)
            }
            ConstantExpr::Mul(x, y) => {
                x.as_ref().to_polish_(res);
                y.as_ref().to_polish_(res);
                res.push(PolishToken::Mul)
            }
            ConstantExpr::Sub(x, y) => {
                x.as_ref().to_polish_(res);
                y.as_ref().to_polish_(res);
                res.push(PolishToken::Sub)
            }
            ConstantExpr::Literal(x) => res.push(PolishToken::Literal(*x)),
            ConstantExpr::Pow(x, n) => {
                x.to_polish_(res);
                res.push(PolishToken::Pow(*n))
            }
        }
    }
}

impl<F: Field> ConstantExpr<F> {
    /// Exponentiate a constant expression.
    pub fn pow(self, p: u64) -> Self {
        if p == 0 {
            return Literal(F::one());
        }
        use ConstantExpr::*;
        match self {
            Literal(x) => Literal(x.pow(&[p])),
            x => Pow(Box::new(x), p),
        }
    }

    /// Evaluate the given constant expression to a field element.
    pub fn value(&self, c: &Constants<F>) -> F {
        use ConstantExpr::*;
        match self {
            Alpha => c.alpha,
            Beta => c.beta,
            Gamma => c.gamma,
            JointCombiner => c.joint_combiner.expect("joint lookup was not expected"),
            EndoCoefficient => c.endo_coefficient,
            Mds { row, col } => c.mds[*row][*col],
            ForeignFieldModulus(i) => {
                if let Some(modulus) = c.foreign_field_modulus.clone() {
                    ForeignElement::<F, 3>::from_biguint(modulus)[*i]
                } else {
                    F::zero()
                }
            }
            Literal(x) => *x,
            Pow(x, p) => x.value(c).pow(&[*p as u64]),
            Mul(x, y) => x.value(c) * y.value(c),
            Add(x, y) => x.value(c) + y.value(c),
            Sub(x, y) => x.value(c) - y.value(c),
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
    fn get_from<'a, 'b, F: FftField>(
        &self,
        cache: &'b HashMap<CacheId, EvalResult<'a, F>>,
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

    fn text_name(&self) -> String {
        format!("x[{}]", self.0)
    }
}

impl Cache {
    fn next_id(&mut self) -> CacheId {
        let id = self.next_id;
        self.next_id += 1;
        CacheId(id)
    }

    pub fn cache<F: Field, T: ExprOps<F>>(&mut self, e: T) -> T {
        e.cache(self)
    }
}

/// A binary operation
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Op2 {
    Add,
    Mul,
    Sub,
}

impl Op2 {
    fn to_polish<A>(&self) -> PolishToken<A> {
        use Op2::*;
        match self {
            Add => PolishToken::Add,
            Mul => PolishToken::Mul,
            Sub => PolishToken::Sub,
        }
    }
}

/// The feature flags that can be used to enable or disable parts of constraints.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(
    feature = "ocaml_types",
    derive(ocaml::IntoValue, ocaml::FromValue, ocaml_gen::Enum)
)]
pub enum FeatureFlag {
    ChaCha,
    RangeCheck,
    ForeignFieldAdd,
    Xor,
}

impl FeatureFlag {
    fn is_enabled(&self) -> bool {
        todo!("Handle features")
    }
}

/// An multi-variate polynomial over the base ring `C` with
/// variables
///
/// - `Cell(v)` for `v : Variable`
/// - VanishesOnLast4Rows
/// - UnnormalizedLagrangeBasis(i) for `i : i32`
///
/// This represents a PLONK "custom constraint", which enforces that
/// the corresponding combination of the polynomials corresponding to
/// the above variables should vanish on the PLONK domain.
#[derive(Clone, Debug, PartialEq)]
pub enum Expr<C> {
    Constant(C),
    Cell(Variable),
    Double(Box<Expr<C>>),
    Square(Box<Expr<C>>),
    BinOp(Op2, Box<Expr<C>>, Box<Expr<C>>),
    VanishesOnLast4Rows,
    /// UnnormalizedLagrangeBasis(i) is
    /// (x^n - 1) / (x - omega^i)
    UnnormalizedLagrangeBasis(i32),
    Pow(Box<Expr<C>>, u64),
    Cache(CacheId, Box<Expr<C>>),
    /// Expression is conditional on the given feature flag, returns 0 if disabled.
    EnabledIf(FeatureFlag, Box<Expr<C>>),
}

/// For efficiency of evaluation, we compile expressions to
/// [reverse Polish notation](https://en.wikipedia.org/wiki/Reverse_Polish_notation)
/// expressions, which are vectors of the below tokens.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolishToken<F> {
    Alpha,
    Beta,
    Gamma,
    JointCombiner,
    EndoCoefficient,
    Mds {
        row: usize,
        col: usize,
    },
    ForeignFieldModulus(usize),
    Literal(F),
    Cell(Variable),
    Dup,
    Pow(u64),
    Add,
    Mul,
    Sub,
    VanishesOnLast4Rows,
    UnnormalizedLagrangeBasis(i32),
    Store,
    Load(usize),
    /// Skip the given number of tokens if the feature is disabled, and emit a zero instead.
    SkipIfNot(FeatureFlag, usize),
}

impl Variable {
    fn evaluate<F: Field>(&self, evals: &[ProofEvaluations<F>]) -> Result<F, ExprError> {
        let evals = &evals[self.row.shift()];
        use Column::*;
        let l = evals
            .lookup
            .as_ref()
            .ok_or(ExprError::LookupShouldNotBeUsed);
        match self.col {
            Witness(i) => Ok(evals.w[i]),
            Z => Ok(evals.z),
            LookupSorted(i) => l.map(|l| l.sorted[i]),
            LookupAggreg => l.map(|l| l.aggreg),
            LookupTable => l.map(|l| l.table),
            LookupRuntimeTable => l.and_then(|l| l.runtime.ok_or(ExprError::MissingRuntime)),
            Index(GateType::Poseidon) => Ok(evals.poseidon_selector),
            Index(GateType::Generic) => Ok(evals.generic_selector),
            Coefficient(i) => Ok(evals.coefficients[i]),
            LookupKindIndex(_) | LookupRuntimeSelector | Index(_) => {
                Err(ExprError::MissingIndexEvaluation(self.col))
            }
        }
    }
}

impl<F: FftField> PolishToken<F> {
    /// Evaluate an RPN expression to a field element.
    pub fn evaluate(
        toks: &[PolishToken<F>],
        d: D<F>,
        pt: F,
        evals: &[ProofEvaluations<F>],
        c: &Constants<F>,
    ) -> Result<F, ExprError> {
        let mut stack = vec![];
        let mut cache: Vec<F> = vec![];

        let mut skip_count = 0;

        for t in toks.iter() {
            if skip_count > 0 {
                skip_count -= 1;
                continue;
            }
            use PolishToken::*;
            match t {
                Alpha => stack.push(c.alpha),
                Beta => stack.push(c.beta),
                Gamma => stack.push(c.gamma),
                JointCombiner => {
                    stack.push(c.joint_combiner.expect("no joint lookup was expected"))
                }
                EndoCoefficient => stack.push(c.endo_coefficient),
                Mds { row, col } => stack.push(c.mds[*row][*col]),
                ForeignFieldModulus(i) => {
                    if let Some(modulus) = c.foreign_field_modulus.clone() {
                        stack.push(ForeignElement::<F, 3>::from_biguint(modulus.clone())[*i])
                    }
                }
                VanishesOnLast4Rows => stack.push(eval_vanishes_on_last_4_rows(d, pt)),
                UnnormalizedLagrangeBasis(i) => {
                    stack.push(unnormalized_lagrange_basis(&d, *i, &pt))
                }
                Literal(x) => stack.push(*x),
                Dup => stack.push(stack[stack.len() - 1]),
                Cell(v) => match v.evaluate(evals) {
                    Ok(x) => stack.push(x),
                    Err(e) => return Err(e),
                },
                Pow(n) => {
                    let i = stack.len() - 1;
                    stack[i] = stack[i].pow(&[*n as u64]);
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

impl<C> Expr<C> {
    /// Convenience function for constructing cell variables.
    pub fn cell(col: Column, row: CurrOrNext) -> Expr<C> {
        Expr::Cell(Variable { col, row })
    }

    pub fn double(self) -> Self {
        Expr::Double(Box::new(self))
    }

    pub fn square(self) -> Self {
        Expr::Square(Box::new(self))
    }

    /// Convenience function for constructing constant expressions.
    pub fn constant(c: C) -> Expr<C> {
        Expr::Constant(c)
    }

    fn degree(&self, d1_size: u64) -> u64 {
        use Expr::*;
        match self {
            Double(x) => x.degree(d1_size),
            Constant(_) => 0,
            VanishesOnLast4Rows => 4,
            UnnormalizedLagrangeBasis(_) => d1_size,
            Cell(_) => d1_size,
            Square(x) => 2 * x.degree(d1_size),
            BinOp(Op2::Mul, x, y) => (*x).degree(d1_size) + (*y).degree(d1_size),
            BinOp(Op2::Add, x, y) | BinOp(Op2::Sub, x, y) => {
                std::cmp::max((*x).degree(d1_size), (*y).degree(d1_size))
            }
            Pow(e, d) => d * e.degree(d1_size),
            Cache(_, e) => e.degree(d1_size),
            EnabledIf(_, e) => e.degree(d1_size),
        }
    }
}

impl<F> fmt::Display for Expr<ConstantExpr<F>>
where
    F: PrimeField,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.text_str())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, FromPrimitive, ToPrimitive)]
enum Domain {
    D1 = 1,
    D2 = 2,
    D4 = 4,
    D8 = 8,
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

/// Compute the powers of `x`, `x^0, ..., x^{n - 1}`
pub fn pows<F: Field>(x: F, n: usize) -> Vec<F> {
    if n == 0 {
        return vec![F::one()];
    } else if n == 1 {
        return vec![F::one(), x];
    }
    let mut v = vec![F::one(), x];
    for i in 2..n {
        v.push(v[i - 1] * x);
    }
    v
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
fn unnormalized_lagrange_evals<F: FftField>(
    l0_1: F,
    i: i32,
    res_domain: Domain,
    env: &Environment<F>,
) -> Evaluations<F, D<F>> {
    let k = match res_domain {
        Domain::D1 => 1,
        Domain::D2 => 2,
        Domain::D4 => 4,
        Domain::D8 => 8,
    };
    let res_domain = get_domain(res_domain, env);

    let d1 = env.domain.d1;
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
    let omega_i = omega.pow(&[ii]);
    let omega_minus_i = omega.pow(&[n - ii]);

    // Write res_domain = < omega_k > with
    // |res_domain| = k * |H|

    // omega_k^0, ..., omega_k^k
    let omega_k_n_pows = pows(res_domain.group_gen.pow(&[n]), k);
    let omega_k_pows = pows(res_domain.group_gen, k);

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

impl<'a, F: FftField> EvalResult<'a, F> {
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

    fn init<G: Sync + Send + Fn(usize) -> F>(res_domain: (Domain, D<F>), g: G) -> Self {
        Self::Evals {
            domain: res_domain.0,
            evals: Self::init_(res_domain, g),
        }
    }

    fn add<'b, 'c>(
        self,
        other: EvalResult<'b, F>,
        res_domain: (Domain, D<F>),
    ) -> EvalResult<'c, F> {
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
                assert!(scale != 0);
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
                assert!(scale != 0);
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
                assert!(scale1 != 0);
                let scale2 = (d2 as usize) / (res_domain.0 as usize);
                assert!(scale2 != 0);

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

    fn sub<'b, 'c>(
        self,
        other: EvalResult<'b, F>,
        res_domain: (Domain, D<F>),
    ) -> EvalResult<'c, F> {
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
                assert!(scale != 0);
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
                assert!(scale != 0);
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
                assert!(scale != 0);
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
                assert!(scale != 0);
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
                assert!(scale1 != 0);
                let scale2 = (d2 as usize) / (res_domain.0 as usize);
                assert!(scale2 != 0);

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
                assert!(scale != 0);
                EvalResult::init(res_domain, |i| {
                    evals.evals[(scale * i + (d as usize) * s) % evals.evals.len()].square()
                })
            }
        }
    }

    fn mul<'b, 'c>(
        self,
        other: EvalResult<'b, F>,
        res_domain: (Domain, D<F>),
    ) -> EvalResult<'c, F> {
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
                assert!(scale != 0);
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
                assert!(scale != 0);
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
                assert!(scale1 != 0);
                let scale2 = (d2 as usize) / (res_domain.0 as usize);
                assert!(scale2 != 0);

                EvalResult::init(res_domain, |i| {
                    es1.evals[(scale1 * i + (d1 as usize) * s1) % es1.evals.len()]
                        * es2.evals[(scale2 * i + (d2 as usize) * s2) % es2.evals.len()]
                })
            }
        }
    }
}

fn get_domain<F: FftField>(d: Domain, env: &Environment<F>) -> D<F> {
    match d {
        Domain::D1 => env.domain.d1,
        Domain::D2 => env.domain.d2,
        Domain::D4 => env.domain.d4,
        Domain::D8 => env.domain.d8,
    }
}

impl<F: Field> Expr<ConstantExpr<F>> {
    /// Convenience function for constructing expressions from literal
    /// field elements.
    pub fn literal(x: F) -> Self {
        Expr::Constant(ConstantExpr::Literal(x))
    }

    /// Combines multiple constraints `[c0, ..., cn]` into a single constraint
    /// `alpha^alpha0 * c0 + alpha^{alpha0 + 1} * c1 + ... + alpha^{alpha0 + n} * cn`.
    pub fn combine_constraints(alphas: impl Iterator<Item = u32>, cs: Vec<Self>) -> Self {
        let zero = Expr::<ConstantExpr<F>>::zero();
        cs.into_iter()
            .zip_eq(alphas)
            .map(|(c, i)| Expr::Constant(ConstantExpr::Alpha.pow(i as u64)) * c)
            .fold(zero, |acc, x| acc + x)
    }
}

impl<F: FftField> Expr<ConstantExpr<F>> {
    /// Compile an expression to an RPN expression.
    pub fn to_polish(&self) -> Vec<PolishToken<F>> {
        let mut res = vec![];
        let mut cache = HashMap::new();
        self.to_polish_(&mut cache, &mut res);
        res
    }

    fn to_polish_(&self, cache: &mut HashMap<CacheId, usize>, res: &mut Vec<PolishToken<F>>) {
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
            Expr::Constant(c) => {
                c.to_polish_(res);
            }
            Expr::Cell(v) => res.push(PolishToken::Cell(*v)),
            Expr::VanishesOnLast4Rows => {
                res.push(PolishToken::VanishesOnLast4Rows);
            }
            Expr::UnnormalizedLagrangeBasis(i) => {
                res.push(PolishToken::UnnormalizedLagrangeBasis(*i));
            }
            Expr::BinOp(op, x, y) => {
                x.to_polish_(cache, res);
                y.to_polish_(cache, res);
                res.push(op.to_polish());
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
            Expr::EnabledIf(feature, e) => {
                let tok = PolishToken::SkipIfNot(*feature, 0);
                res.push(tok);
                let len_before = res.len();
                /* Clone the cache, to make sure we don't try to access cached statements later
                when the feature flag is off. */
                let mut cache = cache.clone();
                e.to_polish_(&mut cache, res);
                let len_after = res.len();
                res[len_before - 1] = PolishToken::SkipIfNot(*feature, len_after - len_before);
            }
        }
    }

    /// The expression `beta`.
    pub fn beta() -> Self {
        Expr::Constant(ConstantExpr::Beta)
    }

    fn evaluate_constants_(&self, c: &Constants<F>) -> Expr<F> {
        use Expr::*;
        // TODO: Use cache
        match self {
            Double(x) => x.evaluate_constants_(c).double(),
            Pow(x, d) => x.evaluate_constants_(c).pow(*d),
            Square(x) => x.evaluate_constants_(c).square(),
            Constant(x) => Constant(x.value(c)),
            Cell(v) => Cell(*v),
            VanishesOnLast4Rows => VanishesOnLast4Rows,
            UnnormalizedLagrangeBasis(i) => UnnormalizedLagrangeBasis(*i),
            BinOp(Op2::Add, x, y) => x.evaluate_constants_(c) + y.evaluate_constants_(c),
            BinOp(Op2::Mul, x, y) => x.evaluate_constants_(c) * y.evaluate_constants_(c),
            BinOp(Op2::Sub, x, y) => x.evaluate_constants_(c) - y.evaluate_constants_(c),
            Cache(id, e) => Cache(*id, Box::new(e.evaluate_constants_(c))),
            EnabledIf(feature, e) => EnabledIf(*feature, Box::new(e.evaluate_constants_(c))),
        }
    }

    /// Evaluate an expression as a field element against an environment.
    pub fn evaluate(
        &self,
        d: D<F>,
        pt: F,
        evals: &[ProofEvaluations<F>],
        env: &Environment<F>,
    ) -> Result<F, ExprError> {
        self.evaluate_(d, pt, evals, &env.constants)
    }

    /// Evaluate an expression as a field element against the constants.
    pub fn evaluate_(
        &self,
        d: D<F>,
        pt: F,
        evals: &[ProofEvaluations<F>],
        c: &Constants<F>,
    ) -> Result<F, ExprError> {
        use Expr::*;
        match self {
            Double(x) => x.evaluate_(d, pt, evals, c).map(|x| x.double()),
            Constant(x) => Ok(x.value(c)),
            Pow(x, p) => Ok(x.evaluate_(d, pt, evals, c)?.pow(&[*p as u64])),
            BinOp(Op2::Mul, x, y) => {
                let x = (*x).evaluate_(d, pt, evals, c)?;
                let y = (*y).evaluate_(d, pt, evals, c)?;
                Ok(x * y)
            }
            Square(x) => Ok(x.evaluate_(d, pt, evals, c)?.square()),
            BinOp(Op2::Add, x, y) => {
                let x = (*x).evaluate_(d, pt, evals, c)?;
                let y = (*y).evaluate_(d, pt, evals, c)?;
                Ok(x + y)
            }
            BinOp(Op2::Sub, x, y) => {
                let x = (*x).evaluate_(d, pt, evals, c)?;
                let y = (*y).evaluate_(d, pt, evals, c)?;
                Ok(x - y)
            }
            VanishesOnLast4Rows => Ok(eval_vanishes_on_last_4_rows(d, pt)),
            UnnormalizedLagrangeBasis(i) => Ok(unnormalized_lagrange_basis(&d, *i, &pt)),
            Cell(v) => v.evaluate(evals),
            Cache(_, e) => e.evaluate_(d, pt, evals, c),
            EnabledIf(feature, e) if feature.is_enabled() => e.evaluate_(d, pt, evals, c),
            EnabledIf(feature, e) => Ok(F::zero()),
        }
    }

    /// Evaluate the constant expressions in this expression down into field elements.
    pub fn evaluate_constants(&self, env: &Environment<F>) -> Expr<F> {
        self.evaluate_constants_(&env.constants)
    }

    /// Compute the polynomial corresponding to this expression, in evaluation form.
    pub fn evaluations<'a>(&self, env: &Environment<'a, F>) -> Evaluations<F, D<F>> {
        self.evaluate_constants(env).evaluations(env)
    }
}

enum Either<A, B> {
    Left(A),
    Right(B),
}

impl<F: FftField> Expr<F> {
    /// Evaluate an expression into a field element.
    pub fn evaluate(&self, d: D<F>, pt: F, evals: &[ProofEvaluations<F>]) -> Result<F, ExprError> {
        use Expr::*;
        match self {
            Constant(x) => Ok(*x),
            Pow(x, p) => Ok(x.evaluate(d, pt, evals)?.pow(&[*p as u64])),
            Double(x) => x.evaluate(d, pt, evals).map(|x| x.double()),
            Square(x) => x.evaluate(d, pt, evals).map(|x| x.square()),
            BinOp(Op2::Mul, x, y) => {
                let x = (*x).evaluate(d, pt, evals)?;
                let y = (*y).evaluate(d, pt, evals)?;
                Ok(x * y)
            }
            BinOp(Op2::Add, x, y) => {
                let x = (*x).evaluate(d, pt, evals)?;
                let y = (*y).evaluate(d, pt, evals)?;
                Ok(x + y)
            }
            BinOp(Op2::Sub, x, y) => {
                let x = (*x).evaluate(d, pt, evals)?;
                let y = (*y).evaluate(d, pt, evals)?;
                Ok(x - y)
            }
            VanishesOnLast4Rows => Ok(eval_vanishes_on_last_4_rows(d, pt)),
            UnnormalizedLagrangeBasis(i) => Ok(unnormalized_lagrange_basis(&d, *i, &pt)),
            Cell(v) => v.evaluate(evals),
            Cache(_, e) => e.evaluate(d, pt, evals),
            EnabledIf(feature, e) => {
                if feature.is_enabled() {
                    e.evaluate(d, pt, evals)
                } else {
                    Ok(F::zero())
                }
            }
        }
    }

    /// Compute the polynomial corresponding to this expression, in evaluation form.
    pub fn evaluations<'a>(&self, env: &Environment<'a, F>) -> Evaluations<F, D<F>> {
        let d1_size = env.domain.d1.size;
        let deg = self.degree(d1_size);
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
            EvalResult::Constant(x) => EvalResult::init_((d, get_domain(d, env)), |_| x),
            EvalResult::SubEvals {
                evals,
                domain: d_sub,
                shift: s,
            } => {
                let res_domain = get_domain(d, env);
                let scale = (d_sub as usize) / (d as usize);
                assert!(scale != 0);
                EvalResult::init_((d, res_domain), |i| {
                    evals.evals[(scale * i + (d_sub as usize) * s) % evals.evals.len()]
                })
            }
        }
    }

    fn evaluations_helper<'a, 'b>(
        &self,
        cache: &'b mut HashMap<CacheId, EvalResult<'a, F>>,
        d: Domain,
        env: &Environment<'a, F>,
    ) -> Either<EvalResult<'a, F>, CacheId>
    where
        'a: 'b,
    {
        let dom = (d, get_domain(d, env));

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
                    Either::Left(x) => x.pow(*p, (d, get_domain(d, env))),
                    Either::Right(id) => {
                        id.get_from(cache).unwrap().pow(*p, (d, get_domain(d, env)))
                    }
                }
            }
            Expr::VanishesOnLast4Rows => EvalResult::SubEvals {
                domain: Domain::D8,
                shift: 0,
                evals: env.vanishes_on_last_4_rows,
            },
            Expr::Constant(x) => EvalResult::Constant(*x),
            Expr::UnnormalizedLagrangeBasis(i) => EvalResult::Evals {
                domain: d,
                evals: unnormalized_lagrange_evals(env.l0_1, *i, d, env),
            },
            Expr::Cell(Variable { col, row }) => {
                let evals: &'a Evaluations<F, D<F>> = {
                    match env.get_column(col) {
                        None => return Either::Left(EvalResult::Constant(F::zero())),
                        Some(e) => e,
                    }
                };
                EvalResult::SubEvals {
                    domain: col.domain(),
                    shift: row.shift(),
                    evals,
                }
            }
            Expr::BinOp(op, e1, e2) => {
                let dom = (d, get_domain(d, env));
                let f = |x: EvalResult<F>, y: EvalResult<F>| match op {
                    Op2::Mul => x.mul(y, dom),
                    Op2::Add => x.add(y, dom),
                    Op2::Sub => x.sub(y, dom),
                };
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
            Expr::EnabledIf(feature, e) => {
                if feature.is_enabled() {
                    /* Clone the cache, to make sure we don't try to access cached statements later
                    when the feature flag is off. */
                    let mut cache = cache.clone();
                    return e.evaluations_helper(&mut cache, d, env);
                } else {
                    EvalResult::Constant(F::zero())
                }
            }
        };
        Either::Left(res)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
/// A "linearization", which is linear combination with `E` coefficients of
/// columns.
pub struct Linearization<E> {
    pub constant_term: E,
    pub index_terms: Vec<(Column, E)>,
}

impl<E: Default> Default for Linearization<E> {
    fn default() -> Self {
        Linearization {
            constant_term: E::default(),
            index_terms: vec![],
        }
    }
}

impl<A> Linearization<A> {
    /// Apply a function to all the coefficients in the linearization.
    pub fn map<B, F: Fn(&A) -> B>(&self, f: F) -> Linearization<B> {
        Linearization {
            constant_term: f(&self.constant_term),
            index_terms: self.index_terms.iter().map(|(c, x)| (*c, f(x))).collect(),
        }
    }
}

impl<F: FftField> Linearization<Expr<ConstantExpr<F>>> {
    /// Evaluate the constants in a linearization with `ConstantExpr<F>` coefficients down
    /// to literal field elements.
    pub fn evaluate_constants(&self, env: &Environment<F>) -> Linearization<Expr<F>> {
        self.map(|e| e.evaluate_constants(env))
    }
}

impl<F: FftField> Linearization<Vec<PolishToken<F>>> {
    /// Given a linearization and an environment, compute the polynomial corresponding to the
    /// linearization, in evaluation form.
    pub fn to_polynomial(
        &self,
        env: &Environment<F>,
        pt: F,
        evals: &[ProofEvaluations<F>],
    ) -> (F, DensePolynomial<F>) {
        let cs = &env.constants;
        let n = env.domain.d1.size();
        let mut res = vec![F::zero(); n];
        self.index_terms.iter().for_each(|(idx, c)| {
            let c = PolishToken::evaluate(c, env.domain.d1, pt, evals, cs).unwrap();
            let e = env
                .get_column(idx)
                .unwrap_or_else(|| panic!("Index polynomial {:?} not found", idx));
            let scale = e.evals.len() / n;
            res.par_iter_mut()
                .enumerate()
                .for_each(|(i, r)| *r += c * e.evals[scale * i]);
        });
        let p = Evaluations::<F, D<F>>::from_vec_and_domain(res, env.domain.d1).interpolate();
        (
            PolishToken::evaluate(&self.constant_term, env.domain.d1, pt, evals, cs).unwrap(),
            p,
        )
    }
}

impl<F: FftField> Linearization<Expr<ConstantExpr<F>>> {
    /// Given a linearization and an environment, compute the polynomial corresponding to the
    /// linearization, in evaluation form.
    pub fn to_polynomial(
        &self,
        env: &Environment<F>,
        pt: F,
        evals: &[ProofEvaluations<F>],
    ) -> (F, DensePolynomial<F>) {
        let cs = &env.constants;
        let n = env.domain.d1.size();
        let mut res = vec![F::zero(); n];
        self.index_terms.iter().for_each(|(idx, c)| {
            let c = c.evaluate_(env.domain.d1, pt, evals, cs).unwrap();
            let e = env
                .get_column(idx)
                .unwrap_or_else(|| panic!("Index polynomial {:?} not found", idx));
            let scale = e.evals.len() / n;
            res.par_iter_mut()
                .enumerate()
                .for_each(|(i, r)| *r += c * e.evals[scale * i])
        });
        let p = Evaluations::<F, D<F>>::from_vec_and_domain(res, env.domain.d1).interpolate();
        (
            self.constant_term
                .evaluate_(env.domain.d1, pt, evals, cs)
                .unwrap(),
            p,
        )
    }
}

impl<F: One> Expr<F> {
    /// Exponentiate an expression
    #[must_use]
    pub fn pow(self, p: u64) -> Self {
        use Expr::*;
        if p == 0 {
            return Constant(F::one());
        }
        Pow(Box::new(self), p)
    }
}

type Monomials<F> = HashMap<Vec<Variable>, Expr<F>>;

fn mul_monomials<F: Neg<Output = F> + Clone + One + Zero + PartialEq>(
    e1: &Monomials<F>,
    e2: &Monomials<F>,
) -> Monomials<F> {
    let mut res: HashMap<_, Expr<F>> = HashMap::new();
    for (m1, c1) in e1.iter() {
        for (m2, c2) in e2.iter() {
            let mut m = m1.clone();
            m.extend(m2);
            m.sort();
            let c1c2 = c1.clone() * c2.clone();
            let v = res.entry(m).or_insert_with(Expr::<F>::zero);
            *v = v.clone() + c1c2;
        }
    }
    res
}

impl<F: Neg<Output = F> + Clone + One + Zero + PartialEq> Expr<F> {
    // TODO: This function (which takes linear time)
    // is called repeatedly in monomials, yielding quadratic behavior for
    // that function. It's ok for now as we only call that function once on
    // a small input when producing the verification key.
    fn is_constant(&self, evaluated: &HashSet<Column>) -> bool {
        use Expr::*;
        match self {
            Pow(x, _) => x.is_constant(evaluated),
            Square(x) => x.is_constant(evaluated),
            Constant(_) => true,
            Cell(v) => evaluated.contains(&v.col),
            Double(x) => x.is_constant(evaluated),
            BinOp(_, x, y) => x.is_constant(evaluated) && y.is_constant(evaluated),
            VanishesOnLast4Rows => true,
            UnnormalizedLagrangeBasis(_) => true,
            Cache(_, x) => x.is_constant(evaluated),
            EnabledIf(_, x) => x.is_constant(evaluated),
        }
    }

    fn monomials(&self, ev: &HashSet<Column>) -> HashMap<Vec<Variable>, Expr<F>> {
        let sing = |v: Vec<Variable>, c: Expr<F>| {
            let mut h = HashMap::new();
            h.insert(v, c);
            h
        };
        let constant = |e: Expr<F>| sing(vec![], e);
        use Expr::*;

        if self.is_constant(ev) {
            return constant(self.clone());
        }

        match self {
            Pow(x, d) => {
                // Run the multiplication logic with square and multiply
                let mut acc = sing(vec![], Expr::<F>::one());
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
            UnnormalizedLagrangeBasis(i) => constant(UnnormalizedLagrangeBasis(*i)),
            VanishesOnLast4Rows => constant(VanishesOnLast4Rows),
            Constant(c) => constant(Constant(c.clone())),
            Cell(var) => sing(vec![*var], Constant(F::one())),
            BinOp(Op2::Add, e1, e2) => {
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
            BinOp(Op2::Sub, e1, e2) => {
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
            BinOp(Op2::Mul, e1, e2) => {
                let e1 = e1.monomials(ev);
                let e2 = e2.monomials(ev);
                mul_monomials(&e1, &e2)
            }
            Square(x) => {
                let x = x.monomials(ev);
                mul_monomials(&x, &x)
            }
            EnabledIf(feature, x) => {
                let e = x.monomials(ev);
                HashMap::from_iter(
                    e.into_iter()
                        .map(|(m, c)| (m, Expr::EnabledIf(*feature, Box::new(c)))),
                )
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
    /// `lin_or_err : (F[V_1])[V_0] -> Result<Vec<(V_0, F[V_2])>, &str>`
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
    ) -> Result<Linearization<Expr<F>>, ExprError> {
        let mut res: HashMap<Column, Expr<F>> = HashMap::new();
        let mut constant_term: Expr<F> = Self::zero();
        let monomials = self.monomials(&evaluated);

        for (m, c) in monomials {
            let (evaluated, mut unevaluated): (Vec<_>, _) =
                m.into_iter().partition(|v| evaluated.contains(&v.col));
            let c = evaluated.into_iter().fold(c, |acc, v| acc * Expr::Cell(v));
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
                return Err(ExprError::FailedLinearization);
            }
        }
        Ok(Linearization {
            constant_term,
            index_terms: res.into_iter().collect(),
        })
    }
}

// Trait implementations

impl<F: Field> Zero for ConstantExpr<F> {
    fn zero() -> Self {
        ConstantExpr::Literal(F::zero())
    }

    fn is_zero(&self) -> bool {
        match self {
            ConstantExpr::Literal(x) => x.is_zero(),
            _ => false,
        }
    }
}

impl<F: Field> One for ConstantExpr<F> {
    fn one() -> Self {
        ConstantExpr::Literal(F::one())
    }

    fn is_one(&self) -> bool {
        match self {
            ConstantExpr::Literal(x) => x.is_one(),
            _ => false,
        }
    }
}

impl<F: One + Neg<Output = F>> Neg for ConstantExpr<F> {
    type Output = ConstantExpr<F>;

    fn neg(self) -> ConstantExpr<F> {
        match self {
            ConstantExpr::Literal(x) => ConstantExpr::Literal(x.neg()),
            e => ConstantExpr::Mul(Box::new(ConstantExpr::Literal(F::one().neg())), Box::new(e)),
        }
    }
}

impl<F: Field> Add<ConstantExpr<F>> for ConstantExpr<F> {
    type Output = ConstantExpr<F>;
    fn add(self, other: Self) -> Self {
        use ConstantExpr::{Add, Literal};
        if self.is_zero() {
            return other;
        }
        if other.is_zero() {
            return self;
        }
        match (self, other) {
            (Literal(x), Literal(y)) => Literal(x + y),
            (x, y) => Add(Box::new(x), Box::new(y)),
        }
    }
}

impl<F: Field> Sub<ConstantExpr<F>> for ConstantExpr<F> {
    type Output = ConstantExpr<F>;
    fn sub(self, other: Self) -> Self {
        use ConstantExpr::{Literal, Sub};
        if other.is_zero() {
            return self;
        }
        match (self, other) {
            (Literal(x), Literal(y)) => Literal(x - y),
            (x, y) => Sub(Box::new(x), Box::new(y)),
        }
    }
}

impl<F: Field> Mul<ConstantExpr<F>> for ConstantExpr<F> {
    type Output = ConstantExpr<F>;
    fn mul(self, other: Self) -> Self {
        use ConstantExpr::{Literal, Mul};
        if self.is_one() {
            return other;
        }
        if other.is_one() {
            return self;
        }
        match (self, other) {
            (Literal(x), Literal(y)) => Literal(x * y),
            (x, y) => Mul(Box::new(x), Box::new(y)),
        }
    }
}

impl<F: Zero> Zero for Expr<F> {
    fn zero() -> Self {
        Expr::Constant(F::zero())
    }

    fn is_zero(&self) -> bool {
        match self {
            Expr::Constant(x) => x.is_zero(),
            _ => false,
        }
    }
}

impl<F: Zero + One + PartialEq> One for Expr<F> {
    fn one() -> Self {
        Expr::Constant(F::one())
    }

    fn is_one(&self) -> bool {
        match self {
            Expr::Constant(x) => x.is_one(),
            _ => false,
        }
    }
}

impl<F: One + Neg<Output = F>> Neg for Expr<F> {
    type Output = Expr<F>;

    fn neg(self) -> Expr<F> {
        match self {
            Expr::Constant(x) => Expr::Constant(x.neg()),
            e => Expr::BinOp(
                Op2::Mul,
                Box::new(Expr::Constant(F::one().neg())),
                Box::new(e),
            ),
        }
    }
}

impl<F: Zero> Add<Expr<F>> for Expr<F> {
    type Output = Expr<F>;
    fn add(self, other: Self) -> Self {
        if self.is_zero() {
            return other;
        }
        if other.is_zero() {
            return self;
        }
        Expr::BinOp(Op2::Add, Box::new(self), Box::new(other))
    }
}

impl<F: Zero + Clone> AddAssign<Expr<F>> for Expr<F> {
    fn add_assign(&mut self, other: Self) {
        if self.is_zero() {
            *self = other;
        } else if !other.is_zero() {
            *self = Expr::BinOp(Op2::Add, Box::new(self.clone()), Box::new(other));
        }
    }
}

impl<F: Zero + One + PartialEq> Mul<Expr<F>> for Expr<F> {
    type Output = Expr<F>;
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
        Expr::BinOp(Op2::Mul, Box::new(self), Box::new(other))
    }
}

impl<F> MulAssign<Expr<F>> for Expr<F>
where
    F: Zero + One + PartialEq + Clone,
{
    fn mul_assign(&mut self, other: Self) {
        if self.is_zero() || other.is_zero() {
            *self = Self::zero();
        } else if self.is_one() {
            *self = other;
        } else if !other.is_one() {
            *self = Expr::BinOp(Op2::Mul, Box::new(self.clone()), Box::new(other));
        }
    }
}

impl<F: Zero> Sub<Expr<F>> for Expr<F> {
    type Output = Expr<F>;
    fn sub(self, other: Self) -> Self {
        if other.is_zero() {
            return self;
        }
        Expr::BinOp(Op2::Sub, Box::new(self), Box::new(other))
    }
}

impl<F: Field> From<u64> for Expr<F> {
    fn from(x: u64) -> Self {
        Expr::Constant(F::from(x))
    }
}

impl<F: Field> From<u64> for Expr<ConstantExpr<F>> {
    fn from(x: u64) -> Self {
        Expr::Constant(ConstantExpr::Literal(F::from(x)))
    }
}

impl<F: Field> From<u64> for ConstantExpr<F> {
    fn from(x: u64) -> Self {
        ConstantExpr::Literal(F::from(x))
    }
}

impl<F: Field> Mul<F> for Expr<ConstantExpr<F>> {
    type Output = Expr<ConstantExpr<F>>;

    fn mul(self, y: F) -> Self::Output {
        Expr::Constant(ConstantExpr::Literal(y)) * self
    }
}

//
// Display
//

impl<F> ConstantExpr<F>
where
    F: PrimeField,
{
    fn ocaml(&self) -> String {
        use ConstantExpr::*;
        match self {
            Alpha => "alpha".to_string(),
            Beta => "beta".to_string(),
            Gamma => "gamma".to_string(),
            JointCombiner => "joint_combiner".to_string(),
            EndoCoefficient => "endo_coefficient".to_string(),
            Mds { row, col } => format!("mds({row}, {col})"),
            ForeignFieldModulus(i) => format!("foreign_field_modulus({i})"),
            Literal(x) => format!("field(\"0x{}\")", x.into_repr()),
            Pow(x, n) => match x.as_ref() {
                Alpha => format!("alpha_pow({n})"),
                x => format!("pow({}, {n})", x.ocaml()),
            },
            Add(x, y) => format!("({} + {})", x.ocaml(), y.ocaml()),
            Mul(x, y) => format!("({} * {})", x.ocaml(), y.ocaml()),
            Sub(x, y) => format!("({} - {})", x.ocaml(), y.ocaml()),
        }
    }

    fn latex(&self) -> String {
        use ConstantExpr::*;
        match self {
            Alpha => "\\alpha".to_string(),
            Beta => "\\beta".to_string(),
            Gamma => "\\gamma".to_string(),
            JointCombiner => "joint\\_combiner".to_string(),
            EndoCoefficient => "endo\\_coefficient".to_string(),
            Mds { row, col } => format!("mds({row}, {col})"),
            ForeignFieldModulus(i) => format!("foreign\\_field\\_modulus({i})"),
            Literal(x) => format!("\\mathbb{{F}}({})", x.into_repr().into()),
            Pow(x, n) => match x.as_ref() {
                Alpha => format!("\\alpha^{{{n}}}"),
                x => format!("{}^{n}", x.ocaml()),
            },
            Add(x, y) => format!("({} + {})", x.ocaml(), y.ocaml()),
            Mul(x, y) => format!("({} \\cdot {})", x.ocaml(), y.ocaml()),
            Sub(x, y) => format!("({} - {})", x.ocaml(), y.ocaml()),
        }
    }

    fn text(&self) -> String {
        use ConstantExpr::*;
        match self {
            Alpha => "alpha".to_string(),
            Beta => "beta".to_string(),
            Gamma => "gamma".to_string(),
            JointCombiner => "joint_combiner".to_string(),
            EndoCoefficient => "endo_coefficient".to_string(),
            Mds { row, col } => format!("mds({row}, {col})"),
            ForeignFieldModulus(i) => format!("foreign_field_modulus({i})"),
            Literal(x) => format!("0x{}", x.to_hex()),
            Pow(x, n) => match x.as_ref() {
                Alpha => format!("alpha^{}", n),
                x => format!("{}^{n}", x.text()),
            },
            Add(x, y) => format!("({} + {})", x.text(), y.text()),
            Mul(x, y) => format!("({} * {})", x.text(), y.text()),
            Sub(x, y) => format!("({} - {})", x.text(), y.text()),
        }
    }
}

impl<F> Expr<ConstantExpr<F>>
where
    F: PrimeField,
{
    /// Converts the expression in OCaml code
    pub fn ocaml_str(&self) -> String {
        let mut env = HashMap::new();
        let e = self.ocaml(&mut env);

        let mut env: Vec<_> = env.into_iter().collect();
        // HashMap deliberately uses an unstable order; here we sort to ensure that the output is
        // consistent when printing.
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

    /// Recursively print the expression,
    /// except for the cached expression that are stored in the `cache`.
    fn ocaml(&self, cache: &mut HashMap<CacheId, Expr<ConstantExpr<F>>>) -> String {
        use Expr::*;
        match self {
            Double(x) => format!("double({})", x.ocaml(cache)),
            Constant(x) => x.ocaml(),
            Cell(v) => format!("cell({})", v.ocaml()),
            UnnormalizedLagrangeBasis(i) => format!("unnormalized_lagrange_basis({})", *i),
            VanishesOnLast4Rows => "vanishes_on_last_4_rows".to_string(),
            BinOp(Op2::Add, x, y) => format!("({} + {})", x.ocaml(cache), y.ocaml(cache)),
            BinOp(Op2::Mul, x, y) => format!("({} * {})", x.ocaml(cache), y.ocaml(cache)),
            BinOp(Op2::Sub, x, y) => format!("({} - {})", x.ocaml(cache), y.ocaml(cache)),
            Pow(x, d) => format!("pow({}, {d})", x.ocaml(cache)),
            Square(x) => format!("square({})", x.ocaml(cache)),
            Cache(id, e) => {
                cache.insert(*id, e.as_ref().clone());
                id.var_name()
            }
            EnabledIf(feature, e) => {
                format!("enabled_if({:?}, (fun () -> {}))", feature, e.ocaml(cache))
            }
        }
    }

    /// Converts the expression in LaTeX
    pub fn latex_str(&self) -> Vec<String> {
        let mut env = HashMap::new();
        let e = self.latex(&mut env);

        let mut env: Vec<_> = env.into_iter().collect();
        // HashMap deliberately uses an unstable order; here we sort to ensure that the output is
        // consistent when printing.
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

    fn latex(&self, cache: &mut HashMap<CacheId, Expr<ConstantExpr<F>>>) -> String {
        use Expr::*;
        match self {
            Double(x) => format!("2 ({})", x.latex(cache)),
            Constant(x) => x.latex(),
            Cell(v) => v.latex(),
            UnnormalizedLagrangeBasis(i) => format!("unnormalized\\_lagrange\\_basis({})", *i),
            VanishesOnLast4Rows => "vanishes\\_on\\_last\\_4\\_rows".to_string(),
            BinOp(Op2::Add, x, y) => format!("({} + {})", x.latex(cache), y.latex(cache)),
            BinOp(Op2::Mul, x, y) => format!("({} \\cdot {})", x.latex(cache), y.latex(cache)),
            BinOp(Op2::Sub, x, y) => format!("({} - {})", x.latex(cache), y.latex(cache)),
            Pow(x, d) => format!("{}^{{{d}}}", x.latex(cache)),
            Square(x) => format!("({})^2", x.latex(cache)),
            Cache(id, e) => {
                cache.insert(*id, e.as_ref().clone());
                id.latex_name()
            }
            EnabledIf(feature, _) => format!("{:?}", feature),
        }
    }

    /// Recursively print the expression,
    /// except for the cached expression that are stored in the `cache`.
    fn text(&self, cache: &mut HashMap<CacheId, Expr<ConstantExpr<F>>>) -> String {
        use Expr::*;
        match self {
            Double(x) => format!("double({})", x.text(cache)),
            Constant(x) => x.text(),
            Cell(v) => v.text(),
            UnnormalizedLagrangeBasis(i) => format!("unnormalized_lagrange_basis({})", *i),
            VanishesOnLast4Rows => "vanishes_on_last_4_rows".to_string(),
            BinOp(Op2::Add, x, y) => format!("({} + {})", x.text(cache), y.text(cache)),
            BinOp(Op2::Mul, x, y) => format!("({} * {})", x.text(cache), y.text(cache)),
            BinOp(Op2::Sub, x, y) => format!("({} - {})", x.text(cache), y.text(cache)),
            Pow(x, d) => format!("pow({}, {d})", x.text(cache)),
            Square(x) => format!("square({})", x.text(cache)),
            Cache(id, e) => {
                cache.insert(*id, e.as_ref().clone());
                id.var_name()
            }
            EnabledIf(feature, _) => format!("{:?}", feature),
        }
    }

    /// Converts the expression to a text string
    pub fn text_str(&self) -> String {
        let mut env = HashMap::new();
        let e = self.text(&mut env);

        let mut env: Vec<_> = env.into_iter().collect();
        // HashMap deliberately uses an unstable order; here we sort to ensure that the output is
        // consistent when printing.
        env.sort_by(|(x, _), (y, _)| x.cmp(y));

        let mut res = String::new();
        for (k, v) in env {
            let str = format!("{} = {}", k.text_name(), v.text_str());
            res.push_str(&str);
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
    use std::fmt;

    use crate::circuits::argument::ArgumentData;

    use super::*;

    /// This trait defines a common arithmetic operations interface
    /// that can be used by constraints.  It allows us to reuse
    /// constraint code for witness computation.
    pub trait ExprOps<F>:
        std::ops::Add<Output = Self>
        + std::ops::Sub<Output = Self>
        + std::ops::Neg<Output = Self>
        + std::ops::Mul<Output = Self>
        + std::ops::AddAssign<Self>
        + std::ops::MulAssign<Self>
        + Clone
        + Zero
        + One
        + From<u64>
        + fmt::Display
    // Add more as necessary
    where
        Self: std::marker::Sized,
    {
        /// Double the value
        fn double(&self) -> Self;

        /// Compute the square of this value
        fn square(&self) -> Self;

        /// Raise the value to the given power
        fn pow(&self, p: u64) -> Self;

        /// Constrain to boolean
        fn boolean(&self) -> Self;

        /// Create a literal
        fn literal(x: F) -> Self;

        // Witness variable
        fn witness(row: CurrOrNext, col: usize, env: Option<&ArgumentData<F>>) -> Self;

        /// Coefficient
        fn coeff(col: usize, env: Option<&ArgumentData<F>>) -> Self;

        /// Create a constant
        fn constant(expr: ConstantExpr<F>, env: Option<&ArgumentData<F>>) -> Self;

        /// Cache item
        fn cache(&self, cache: &mut Cache) -> Self;
    }

    impl<F> ExprOps<F> for Expr<ConstantExpr<F>>
    where
        F: PrimeField,
    {
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

        fn literal(x: F) -> Self {
            Expr::Constant(ConstantExpr::Literal(x))
        }

        fn witness(row: CurrOrNext, col: usize, _: Option<&ArgumentData<F>>) -> Self {
            witness(col, row)
        }

        fn coeff(col: usize, _: Option<&ArgumentData<F>>) -> Self {
            coeff(col)
        }

        fn constant(expr: ConstantExpr<F>, _: Option<&ArgumentData<F>>) -> Self {
            Expr::Constant(expr)
        }

        fn cache(&self, cache: &mut Cache) -> Self {
            Expr::Cache(cache.next_id(), Box::new(self.clone()))
        }
    }

    impl<F: Field> ExprOps<F> for F {
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

        fn constant(expr: ConstantExpr<F>, env: Option<&ArgumentData<F>>) -> Self {
            match env {
                Some(data) => expr.value(&data.constants),
                None => panic!("Missing constants"),
            }
        }

        fn cache(&self, _: &mut Cache) -> Self {
            *self
        }
    }

    /// Creates a constraint to enforce that b is either 0 or 1.
    pub fn boolean<F: Field, T: ExprOps<F>>(b: &T) -> T {
        b.square() - b.clone()
    }

    /// Crumb constraint for 2-bit value x
    pub fn crumb<F: Field, T: ExprOps<F>>(x: &T) -> T {
        // Assert x \in [0,3] i.e. assert x*(x - 1)*(x - 2)*(x - 3) == 0
        x.clone()
            * (x.clone() - 1u64.into())
            * (x.clone() - 2u64.into())
            * (x.clone() - 3u64.into())
    }
}

//
// Helpers
//

/// An alias for the intended usage of the expression type in constructing constraints.
pub type E<F> = Expr<ConstantExpr<F>>;

/// Convenience function to create a constant as [Expr].
pub fn constant<F>(x: F) -> E<F> {
    Expr::Constant(ConstantExpr::Literal(x))
}

/// Helper function to quickly create an expression for a witness.
pub fn witness<F>(i: usize, row: CurrOrNext) -> E<F> {
    E::<F>::cell(Column::Witness(i), row)
}

/// Same as [witness] but for the current row.
pub fn witness_curr<F>(i: usize) -> E<F> {
    witness(i, CurrOrNext::Curr)
}

/// Same as [witness] but for the next row.
pub fn witness_next<F>(i: usize) -> E<F> {
    witness(i, CurrOrNext::Next)
}

/// Handy function to quickly create an expression for a gate.
pub fn index<F>(g: GateType) -> E<F> {
    E::<F>::cell(Column::Index(g), CurrOrNext::Curr)
}

pub fn coeff<F>(i: usize) -> E<F> {
    E::<F>::cell(Column::Coefficient(i), CurrOrNext::Curr)
}

/// You can import this module like `use kimchi::circuits::expr::prologue::*` to obtain a number of handy aliases and helpers
pub mod prologue {
    pub use super::{coeff, constant, index, witness, witness_curr, witness_next, E};
}

#[cfg(test)]
pub mod test {
    use super::*;
    use crate::{
        circuits::{
            constraints::ConstraintSystem,
            expr::constraints::ExprOps,
            gate::CircuitGate,
            polynomials::{generic::GenericGateSpec, permutation::ZK_ROWS},
            wires::Wire,
        },
        curve::KimchiCurve,
        prover_index::ProverIndex,
    };
    use ark_ff::UniformRand;
    use commitment_dlog::srs::{endos, SRS};
    use mina_curves::pasta::{Fp, Pallas, Vesta};
    use rand::{prelude::StdRng, SeedableRng};
    use std::array;
    use std::sync::Arc;

    #[test]
    #[should_panic]
    fn test_failed_linearize() {
        // w0 * w1
        let mut expr: E<Fp> = E::zero();
        expr += witness_curr(0);
        expr *= witness_curr(1);

        // since none of w0 or w1 is evaluated this should panic
        let evaluated = HashSet::new();
        expr.linearize(evaluated).unwrap();
    }

    #[test]
    #[should_panic]
    fn test_degree_tracking() {
        // The selector CompleteAdd has degree n-1 (so can be tracked with n evaluations in the domain d1 of size n).
        // Raising a polynomial of degree n-1 to the power 8 makes it degree 8*(n-1) (and so it needs `8(n-1) + 1` evaluations).
        // Since `d8` is of size `8n`, we are still good with that many evaluations to track the new polynomial.
        // Raising it to the power 9 pushes us out of the domain d8, which will panic.
        let mut expr: E<Fp> = E::zero();
        expr += index(GateType::CompleteAdd);
        let expr = expr.pow(9);

        // create a dummy env
        let one = Fp::from(1u32);
        let gates = vec![
            CircuitGate::create_generic_gadget(
                Wire::for_row(0),
                GenericGateSpec::Const(1u32.into()),
                None,
            ),
            CircuitGate::create_generic_gadget(
                Wire::for_row(1),
                GenericGateSpec::Const(1u32.into()),
                None,
            ),
        ];
        let index = {
            let constraint_system = ConstraintSystem::fp_for_testing(gates);
            let mut srs = SRS::<Vesta>::create(constraint_system.domain.d1.size());
            srs.add_lagrange_basis(constraint_system.domain.d1);
            let srs = Arc::new(srs);

            let (endo_q, _endo_r) = endos::<Pallas>();
            ProverIndex::<Vesta>::create(constraint_system, endo_q, srs)
        };

        let witness_cols: [_; COLUMNS] = array::from_fn(|_| DensePolynomial::zero());
        let permutation = DensePolynomial::zero();
        let domain_evals = index.cs.evaluate(&witness_cols, &permutation);

        let env = Environment {
            constants: Constants {
                alpha: one,
                beta: one,
                gamma: one,
                joint_combiner: None,
                endo_coefficient: one,
                mds: &Vesta::sponge_params().mds,
                foreign_field_modulus: None,
            },
            witness: &domain_evals.d8.this.w,
            coefficient: &index.column_evaluations.coefficients8,
            vanishes_on_last_4_rows: &index.cs.precomputations().vanishes_on_last_4_rows,
            z: &domain_evals.d8.this.z,
            l0_1: l0_1(index.cs.domain.d1),
            domain: index.cs.domain,
            index: HashMap::new(),
            lookup: None,
        };

        // this should panic as we don't have a domain large enough
        expr.evaluations(&env);
    }

    #[test]
    fn test_unnormalized_lagrange_basis() {
        let domain = EvaluationDomains::<Fp>::create(2usize.pow(10) + ZK_ROWS as usize)
            .expect("failed to create evaluation domain");
        let rng = &mut StdRng::from_seed([17u8; 32]);

        // Check that both ways of computing lagrange basis give the same result
        let d1_size: i32 = domain.d1.size().try_into().expect("domain size too big");
        for i in 1..d1_size {
            let pt = Fp::rand(rng);
            assert_eq!(
                unnormalized_lagrange_basis(&domain.d1, d1_size - i, &pt),
                unnormalized_lagrange_basis(&domain.d1, -i, &pt)
            );
        }
    }

    #[test]
    fn test_arithmetic_ops() {
        fn test_1<F: Field, T: ExprOps<F>>() -> T {
            T::zero() + T::one()
        }
        assert_eq!(test_1::<Fp, E<Fp>>(), E::zero() + E::one());
        assert_eq!(test_1::<Fp, Fp>(), Fp::one());

        fn test_2<F: Field, T: ExprOps<F>>() -> T {
            T::one() + T::one()
        }
        assert_eq!(test_2::<Fp, E<Fp>>(), E::one() + E::one());
        assert_eq!(test_2::<Fp, Fp>(), Fp::from(2u64));

        fn test_3<F: Field, T: ExprOps<F>>(x: T) -> T {
            T::from(2u64) * x
        }
        assert_eq!(
            test_3::<Fp, E<Fp>>(E::from(3u64)),
            E::from(2u64) * E::from(3u64)
        );
        assert_eq!(test_3(Fp::from(3u64)), Fp::from(6u64));

        fn test_4<F: Field, T: ExprOps<F>>(x: T) -> T {
            x.clone() * (x.square() + T::from(7u64))
        }
        assert_eq!(
            test_4::<Fp, E<Fp>>(E::from(5u64)),
            E::from(5u64) * (Expr::square(E::from(5u64)) + E::from(7u64))
        );
        assert_eq!(test_4::<Fp, Fp>(Fp::from(5u64)), Fp::from(160u64));
    }
}
