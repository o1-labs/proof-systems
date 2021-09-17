use crate::nolookup::scalars::{ProofEvaluations, RandomOracles};
use crate::nolookup::constraints::{eval_zk_polynomial};
use ark_ff::{FftField, Field, Zero, One};
use ark_poly::{Evaluations, EvaluationDomain, Radix2EvaluationDomain as D};
use crate::gate::{GateType, CurrOrNext};
use std::ops::{Add, Sub, Mul};
use std::collections::{HashMap, HashSet};
use CurrOrNext::*;

use crate::wires::COLUMNS;
use crate::domains::EvaluationDomains;

pub struct Constants<F> {
    pub alpha: F,
    pub beta: F,
    pub gamma: F,
    pub joint_combiner: F,
}

// All are evaluations over the D8 domain
pub struct Environment<'a, F : FftField> {
    pub witness: &'a [Evaluations<F, D<F>>; COLUMNS],
    pub zk_polynomial: &'a Evaluations<F, D<F>>,
    pub z: &'a Evaluations<F, D<F>>,
    pub lookup_sorted: &'a Vec<Evaluations<F, D<F>>>,
    pub lookup_aggreg: &'a Evaluations<F, D<F>>,
    pub alpha: F,
    pub beta: F,
    pub gamma: F,
    pub joint_combiner: F,
    pub domain: EvaluationDomains<F>,
    pub index: HashMap<GateType, &'a Evaluations<F, D<F>>>,
    pub lookup_selectors: &'a Vec<Evaluations<F, D<F>>>,
    pub lookup_table: &'a Evaluations<F, D<F>>,
    // The value
    // prod_{j != 1} (1 - omega^j)
    pub l0_1: F,
}

// In this file, we define
//
// l_i(x) to be the unnormalized lagrange polynomial,
// (x^n - 1) / (x - omega^i)
// = prod_{j != i} (x - omega^j)
//
// and L_i(x) to be the normalized lagrange polynomial,
// L_i(x) = l_i(x) / l_i(omega^i)

/// prod_{j != 1} (1 - omega^j)
pub fn l0_1<F:FftField>(d: D<F>) -> F {
    let mut omega_j = d.group_gen;
    let mut res = F::one();
    for _ in 1..(d.size as usize) {
        res *= F::one() - omega_j;
        omega_j *= d.group_gen;
    }
    res
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Column {
    Witness(usize),
    Z,
    LookupSorted(usize),
    LookupAggreg,
    LookupTable,
    LookupKindIndex(usize),
    Index(GateType),
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Variable {
    pub col: Column,
    pub row: CurrOrNext,
}

#[derive(Clone, Debug, PartialEq)]
pub enum ConstantExpr<F> {
    Alpha,
    Beta,
    Gamma,
    JointCombiner,
    Literal(F),
    Pow(Box<ConstantExpr<F>>, usize),
    Mul(Box<ConstantExpr<F>>, Box<ConstantExpr<F>>),
    Add(Box<ConstantExpr<F>>, Box<ConstantExpr<F>>),
    Sub(Box<ConstantExpr<F>>, Box<ConstantExpr<F>>),
}

impl<F: Field> ConstantExpr<F> {
    pub fn pow(self, p: usize) -> Self {
        if p == 0 {
            return Literal(F::one());
        }
        use ConstantExpr::*;
        match self {
            Literal(x) => Literal(x.pow(&[p as u64])),
            x => Pow(Box::new(x), p)
        }
    }

    pub fn value(&self, c: &Constants<F>) -> F {
        use ConstantExpr::*;
        match self {
            Alpha => c.alpha,
            Beta => c.beta,
            Gamma => c.gamma,
            JointCombiner => c.joint_combiner,
            Literal(x) => *x,
            Pow(x, p) => x.value(c).pow(&[*p as u64]),
            Mul(x, y) => x.value(c) * y.value(c),
            Add(x, y) => x.value(c) + y.value(c),
            Sub(x, y) => x.value(c) - y.value(c),
        }
    }
}

impl<F: Field> Zero for ConstantExpr<F> {
    fn zero() -> Self {
        ConstantExpr::Literal(F::zero())
    }

    fn is_zero(&self) -> bool {
        match self {
            ConstantExpr::Literal(x) => x.is_zero(),
            _ => false
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
            _ => false
        }
    }
}

impl<F: Field> Add<ConstantExpr<F>> for ConstantExpr<F> {
    type Output = ConstantExpr<F>;
    fn add(self, other: Self) -> Self {
        use ConstantExpr::*;
        if self.is_zero() {
            return other;
        }
        if other.is_zero() {
            return self
        }
        match (self, other) {
            (Literal(x), Literal(y)) => Literal(x + y),
            (x, y) => Add(Box::new(x), Box::new(y))
        }
    }
}

impl<F: Field> Sub<ConstantExpr<F>> for ConstantExpr<F> {
    type Output = ConstantExpr<F>;
    fn sub(self, other: Self) -> Self {
        use ConstantExpr::*;
        if other.is_zero() {
            return self
        }
        match (self, other) {
            (Literal(x), Literal(y)) => Literal(x - y),
            (x, y) => Sub(Box::new(x), Box::new(y))
        }
    }
}

impl<F: Field> Mul<ConstantExpr<F>> for ConstantExpr<F> {
    type Output = ConstantExpr<F>;
    fn mul(self, other: Self) -> Self {
        use ConstantExpr::*;
        if self.is_one() {
            return other;
        }
        if other.is_one() {
            return self;
        }
        match (self, other) {
            (Literal(x), Literal(y)) => Literal(x * y),
            (x, y) => Mul(Box::new(x), Box::new(y))
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum Expr<C> {
    Constant(C),
    Cell(Variable),
    Mul(Box<Expr<C>>, Box<Expr<C>>),
    Add(Box<Expr<C>>, Box<Expr<C>>),
    Sub(Box<Expr<C>>, Box<Expr<C>>),
    ZkPolynomial,
    /// UnnormalizedLagrangeBasis(i) is
    /// (x^n - 1) / (x - omega^i)
    UnnormalizedLagrangeBasis(usize),
}

impl<F: Zero> Zero for Expr<F> {
    fn zero() -> Self {
        Expr::Constant(F::zero())
    }

    fn is_zero(&self) -> bool {
        match self {
            Expr::Constant(x) => x.is_zero(),
            _ => false
        }
    }
}

impl<F: One + PartialEq> One for Expr<F> {
    fn one() -> Self {
        Expr::Constant(F::one())
    }

    fn is_one(&self) -> bool {
        match self {
            Expr::Constant(x) => x.is_one(),
            _ => false
        }
    }
}

impl<C> Expr<C> {
    /// Convenience function for constructing cells
    pub fn cell(col:Column, row: CurrOrNext) -> Expr<C> {
        Expr::Cell(Variable { col, row })
    }

    fn degree(&self, d1_size: usize) -> usize {
        use Expr::*;
        match self {
            Constant(_) => 0,
            ZkPolynomial => 3,
            UnnormalizedLagrangeBasis(_) => d1_size,
            Cell(_) => d1_size,
            Mul(x, y) => (*x).degree(d1_size) + (*y).degree(d1_size),
            Sub(x, y) | Add(x, y) => std::cmp::max((*x).degree(d1_size), (*y).degree(d1_size)),
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
        Expr::Add(Box::new(self), Box::new(other))
    }
}

impl<F: One + PartialEq> Mul<Expr<F>> for Expr<F> {
    type Output = Expr<F>;
    fn mul(self, other: Self) -> Self {
        if self.is_one() {
            return other;
        }
        if other.is_one() {
            return self;
        }
        Expr::Mul(Box::new(self), Box::new(other))
    }
}

impl<F: Zero> Sub<Expr<F>> for Expr<F> {
    type Output = Expr<F>;
    fn sub(self, other: Self) -> Self {
        if other.is_zero() {
            return self;
        }
        Expr::Sub(Box::new(self), Box::new(other))
    }
}

impl<F: Field> From<u64> for Expr<F> {
    fn from(x : u64) -> Self {
        Expr::Constant(F::from(x))
    }
}

impl<F: Field> From<u64> for Expr<ConstantExpr<F>> {
    fn from(x : u64) -> Self {
        Expr::Constant(ConstantExpr::Literal(F::from(x)))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, FromPrimitive, ToPrimitive)]
enum Domain {
    D1 = 1, D2 = 2, D4 = 4, D8 = 8
}

enum EvalResult<'a, F: FftField> {
    Constant(F),
    Evals { domain: Domain, evals: Evaluations<F, D<F>> },
    SubEvals { domain: Domain, shift: usize, evals : &'a Evaluations<F, D<F>> }
}

// x^0, ..., x^{n - 1}
pub fn pows<F: Field>(x: F, n : usize) -> Vec<F> {
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

// Compute the evaluations of the unnormalized lagrange polynomial on
// H_8 or H_4. Taking H_8 as an example, we show how to compute this
// polynomial on the expanded domain.
//
// Let H = < omega >, |H| = n.
//
// Let l_i(x) be the unnormalized lagrange polynomial,
// (x^n - 1) / (x - omega^i)
// = prod_{j != i} (x - omega^j)
//
// For h in H, h != omega^i,
// l_i(h) = 0.
// l_i(omega^i) 
// = prod_{j != i} (omega^i - omega^j)
// = omega^{i (n - 1)} * prod_{j != i} (1 - omega^{j - i})
// = omega^{i (n - 1)} * prod_{j != 0} (1 - omega^j)
// = omega^{i (n - 1)} * l_0(1)
// = omega^{i n} * omega^{-i} * l_0(1)
// = omega^{-i} * l_0(1)
//
// So it is easy to compute l_i(omega^i) from just l_0(1).
//
// Also, consider the expanded domain H_8 generated by
// an 8nth root of unity omega_8 (where H_8^8 = H).
//
// Let omega_8^k in H_8. Write k = 8 * q + r with r < 8.
// Then
// omega_8^k = (omega_8^8)^q * omega_8^r = omega^q * omega_8^r
//
// l_i(omega_8^k)
// = (omega_8^{k n} - 1) / (omega_8^k - omega^i)
// = (omega^{q n} omega_8^{r n} - 1) / (omega_8^k - omega^i)
// = ((omega_8^n)^r - 1) / (omega_8^k - omega^i)
// = ((omega_8^n)^r - 1) / (omega^q omega_8^r - omega^i)
fn unnormalized_lagrange_evals<F:FftField>(
    l0_1: F, 
    i: usize, 
    res_domain: Domain,
    env: &Environment<F>) -> Evaluations<F, D<F>> {

    let k =
        match res_domain {
            Domain::D1 => 1,
            Domain::D2 => 2,
            Domain::D4 => 4,
            Domain::D8 => 8,
        };
    let res_domain = get_domain(res_domain, env);

    let d1 = env.domain.d1;
    let n = d1.size;
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

    let mut evals : Vec<F> = {
        let mut v = vec![F::one(); k*(n as usize)];
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

    Evaluations::<F, D<F>>::from_vec_and_domain(
        evals,
        res_domain
    )
}

impl<'a, F: FftField> EvalResult<'a, F> {
    fn init_<G: Fn(usize) -> F>(
        res_domain: (Domain, D<F>),
        g : G) -> Evaluations<F, D<F>> {
        let n = res_domain.1.size as usize;
        Evaluations::<F, D<F>>::from_vec_and_domain(
            (0..n).map(g).collect(),
            res_domain.1
        )
    }

    fn init<G: Fn(usize) -> F>(res_domain: (Domain, D<F>), g : G) -> Self {
        Self::Evals {
            domain: res_domain.0,
            evals: Self::init_(res_domain, g)
        }
    }

    fn add(self, other: Self, res_domain: (Domain, D<F>)) -> Self {
        use EvalResult::*;
        match (self, other) {
            (Constant(x), Constant(y)) => Constant(x + y),
            (Evals { domain, mut evals }, Constant(x))
            | (Constant(x), Evals { domain, mut evals }) => {
                for e in evals.evals.iter_mut() {
                    *e += x;
                }
                Evals { domain, evals }
            },
            (SubEvals { evals, domain: d, shift:s }, Constant(x)) |
            (Constant(x), SubEvals { evals, domain: d, shift:s }) => {
                let n = res_domain.1.size as usize;
                let scale = (d as usize) / (res_domain.0 as usize);
                let v: Vec<_> = (0..n).map(|i| {
                    x + evals.evals[(scale * i + (d as usize) * s) % evals.evals.len()]
                }).collect();
                Evals {
                    domain: res_domain.0,
                    evals:
                        Evaluations::<F, D<F>>::from_vec_and_domain(
                            v,
                            res_domain.1
                        )
                }
            },
            (Evals { domain:d1, evals: mut es1 }, Evals { domain:d2, evals: es2 }) => {
                assert_eq!(d1, d2);
                es1 += &es2;
                Evals { domain: d1, evals: es1 }
            },
            (SubEvals { domain: d_sub, shift: s, evals: es_sub }, Evals { domain: d, mut evals })
            | (Evals { domain: d, mut evals }, SubEvals { domain: d_sub, shift: s, evals: es_sub }) => {
                let scale = (d_sub as usize) / (d as usize);
                evals.evals.iter_mut().enumerate().for_each(|(i, e)| {
                    *e += es_sub.evals[(scale * i + (d_sub as usize) * s) % es_sub.evals.len()];
                });
                Evals { evals, domain: d }
            },
            (SubEvals { domain: d1, shift: s1, evals: es1 }, SubEvals { domain: d2, shift: s2, evals: es2 }) => {
                let scale1 = (d1 as usize) / (res_domain.0 as usize);
                let scale2 = (d2 as usize) / (res_domain.0 as usize);

                let n = res_domain.1.size as usize;
                let v: Vec<_> = (0..n).map(|i| {
                    es1.evals[(scale1 * i + (d1 as usize) * s1) % es1.evals.len()] 
                        + es2.evals[(scale2 * i + (d2 as usize) * s2) % es2.evals.len()]
                }).collect();

                Evals {
                    domain: res_domain.0,
                    evals:
                        Evaluations::<F, D<F>>::from_vec_and_domain(
                            v,
                            res_domain.1
                        )
                }
            }
        }
    }

    fn sub(self, other: Self, res_domain: (Domain, D<F>)) -> Self {
        use EvalResult::*;
        match (self, other) {
            (Constant(x), Constant(y)) => Constant(x - y),
            (Evals { domain, mut evals }, Constant(x)) => {
                evals.evals.iter_mut().for_each(|e| *e -= x);
                Evals { domain, evals }
            },
            (Constant(x), Evals { domain, mut evals }) => {
                evals.evals.iter_mut().for_each(|e| *e = x - *e);
                Evals { domain, evals }
            },
            (SubEvals { evals, domain: d, shift:s }, Constant(x)) => {
                let scale = (d as usize) / (res_domain.0 as usize);
                Self::init(
                    res_domain,
                    |i| evals.evals[(scale * i + (d as usize) * s) % evals.evals.len()] - x)
            },
            (Constant(x), SubEvals { evals, domain: d, shift:s }) => {
                let scale = (d as usize) / (res_domain.0 as usize);
                Self::init(
                    res_domain,
                    |i| x - evals.evals[(scale * i + (d as usize) * s) % evals.evals.len()])
            },
            (Evals { domain:d1, evals: mut es1 }, Evals { domain:d2, evals: es2 }) => {
                assert_eq!(d1, d2);
                es1 -= &es2;
                Evals { domain: d1, evals: es1 }
            },
            (SubEvals { domain: d_sub, shift: s, evals: es_sub }, Evals { domain: d, mut evals }) => {
                let scale = (d_sub as usize) / (d as usize);
                evals.evals.iter_mut().enumerate().for_each(|(i, e)| {
                    *e = es_sub.evals[(scale * i + (d_sub as usize) * s) % es_sub.evals.len()] - *e;
                });
                Evals { evals, domain: d }
            }
            (Evals { domain: d, mut evals }, SubEvals { domain: d_sub, shift: s, evals: es_sub }) => {
                let scale = (d_sub as usize) / (d as usize);
                evals.evals.iter_mut().enumerate().for_each(|(i, e)| {
                    *e -= es_sub.evals[(scale * i + (d_sub as usize) * s) % es_sub.evals.len()];
                });
                Evals { evals, domain: d }
            },
            (SubEvals { domain: d1, shift: s1, evals: es1 }, SubEvals { domain: d2, shift: s2, evals: es2 }) => {
                let scale1 = (d1 as usize) / (res_domain.0 as usize);
                let scale2 = (d2 as usize) / (res_domain.0 as usize);

                Self::init(
                    res_domain,
                    |i| es1.evals[(scale1 * i + (d1 as usize) * s1) % es1.evals.len()]
                    - es2.evals[(scale2 * i + (d2 as usize) * s2) % es2.evals.len()])
            }
        }
    }

    fn mul(self, other: Self, res_domain: (Domain, D<F>)) -> Self {
        use EvalResult::*;
        match (self, other) {
            (Constant(x), Constant(y)) => Constant(x * y),
            (Evals { domain, mut evals }, Constant(x))
            | (Constant(x), Evals { domain, mut evals }) => {
                for e in evals.evals.iter_mut() {
                    *e *= x;
                }
                Evals { domain, evals }
            },
            (SubEvals { evals, domain: d, shift:s }, Constant(x)) |
            (Constant(x), SubEvals { evals, domain: d, shift:s }) => {
                let scale = (d as usize) / (res_domain.0 as usize);
                Self::init(
                    res_domain,
                    |i| x * evals.evals[(scale * i + (d as usize) * s) % evals.evals.len()])
            },
            (Evals { domain:d1, evals: mut es1 }, Evals { domain:d2, evals: es2 }) => {
                assert_eq!(d1, d2);
                es1 *= &es2;
                Evals { domain: d1, evals: es1 }
            },
            (SubEvals { domain: d_sub, shift: s, evals: es_sub }, Evals { domain: d, mut evals })
            | (Evals { domain: d, mut evals }, SubEvals { domain: d_sub, shift: s, evals: es_sub }) => {
                let scale = (d_sub as usize) / (d as usize);
                evals.evals.iter_mut().enumerate().for_each(|(i, e)| {
                    *e *= es_sub.evals[(scale * i + (d_sub as usize) * s) % es_sub.evals.len()];
                });
                Evals { evals, domain: d }
            },
            (SubEvals { domain: d1, shift: s1, evals: es1 }, SubEvals { domain: d2, shift: s2, evals: es2 }) => {
                let scale1 = (d1 as usize) / (res_domain.0 as usize);
                let scale2 = (d2 as usize) / (res_domain.0 as usize);

                Self::init(
                    res_domain,
                    |i| es1.evals[(scale1 * i + (d1 as usize) * s1) % es1.evals.len()] * es2.evals[(scale2 * i + (d2 as usize) * s2) % es1.evals.len()])
            }
        }
    }
}

fn get_domain<F: FftField>(d: Domain, env: &Environment<F>) -> D<F> {
    match d {
        Domain::D1 => env.domain.d1,
        Domain::D2 => env.domain.d2,
        Domain::D4 => env.domain.d4,
        Domain::D8 => env.domain.d8
    }
}

fn curr_or_next(row: CurrOrNext) -> usize {
    match row {
        Curr => 0,
        Next => 1
    }
}

impl<F: FftField> Expr<ConstantExpr<F>> {
    pub fn literal(x: F) -> Self {
        Expr::Constant(ConstantExpr::Literal(x))
    }

    pub fn combine_constraints(alpha0: usize, cs: Vec<Self>) -> Self {
        let zero = Expr::<ConstantExpr<F>>::zero();
        cs.into_iter().zip(alpha0..).map(|(c, i)| {
            Expr::Constant(ConstantExpr::Alpha.pow(i)) * c
        }).fold(zero, |acc, x| acc + x)
    }

    pub fn beta() -> Self {
        Expr::Constant(ConstantExpr::Beta)
    }

    pub fn evaluate_constants(&self, c: &Constants<F>) -> Expr<F> {
        use Expr::*;
        match self {
            Constant(x) => Constant(x.value(c)),
            Cell(v) => Cell(*v),
            ZkPolynomial => ZkPolynomial,
            UnnormalizedLagrangeBasis(i) => UnnormalizedLagrangeBasis(*i),
            Add(x, y) => Add(Box::new(x.evaluate_constants(c)), Box::new(y.evaluate_constants(c))),
            Mul(x, y) => Mul(Box::new(x.evaluate_constants(c)), Box::new(y.evaluate_constants(c))),
            Sub(x, y) => Sub(Box::new(x.evaluate_constants(c)), Box::new(y.evaluate_constants(c))),
        }
    }

    pub fn evaluations<'a>(&self, env: &Environment<'a, F>) -> Evaluations<F, D<F>> {
        let c = Constants {
            alpha: env.alpha,
            beta: env.beta,
            gamma: env.gamma,
            joint_combiner: env.joint_combiner
        };
        let e = self.evaluate_constants(&c);
        e.evaluations(env)
    }
}

impl<F: FftField> Expr<F> {
    pub fn evaluate(
        &self, d: D<F>, pt: F, oracles: &RandomOracles<F>, 
        evals: &[ProofEvaluations<F>; 2]) -> Result<F, &str> {
        use Expr::*;
        match self {
            Constant(x) => Ok(*x),
            Mul(x, y) => {
                let x = (*x).evaluate(d, pt, oracles, evals)?;
                let y = (*y).evaluate(d, pt, oracles, evals)?;
                Ok(x * y)
            },
            Add(x, y) => {
                let x = (*x).evaluate(d, pt, oracles, evals)?;
                let y = (*y).evaluate(d, pt, oracles, evals)?;
                Ok(x + y)
            },
            Sub(x, y) => {
                let x = (*x).evaluate(d, pt, oracles, evals)?;
                let y = (*y).evaluate(d, pt, oracles, evals)?;
                Ok(x - y)
            },
            ZkPolynomial => Ok(eval_zk_polynomial(d, pt)),
            UnnormalizedLagrangeBasis(i) => 
                Ok(d.evaluate_vanishing_polynomial(pt) / (pt - d.group_gen.pow(&[*i as u64]))),
            Cell(Variable { col, row }) => {
                let evals = &evals[curr_or_next(*row)];
                use Column::*;
                let lookup_evals =
                    match &evals.lookup {
                        Some(l) => Ok(l),
                        None => Err("Lookup should not have been used")
                    };
                match col {
                    Witness(i) => Ok(evals.w[*i]),
                    Z => Ok(evals.z),
                    LookupSorted(i) => lookup_evals.map(|l| l.sorted[*i]),
                    LookupAggreg => lookup_evals.map(|l| l.aggreg),
                    LookupTable => lookup_evals.map(|l| l.table),
                    LookupKindIndex(_) | Index(_) =>
                        Err("Cannot get index evaluation (should have been linearized away)")
                }
            }
        }
    }

    pub fn evaluations<'a>(&self, env: &Environment<'a, F>) -> Evaluations<F, D<F>> {
        let d1_size = env.domain.d1.size as usize;
        let deg = self.degree(d1_size);
        let d =
            if deg <= d1_size {
                Domain::D1
            } else if deg <= 4 * d1_size {
                Domain::D4
            } else if deg <= 8 * d1_size {
                Domain::D8
            } else {
                panic!("constraint had degree {} > 8", deg);
            };

        match self.evaluations_(d, env) {
            EvalResult::Evals { evals, domain } => {
                assert_eq!(domain, d);
                evals
            },
            EvalResult::Constant(x) => 
                EvalResult::init_((d, get_domain(d, env)), |_| x),
            EvalResult::SubEvals { evals, domain: d_sub, shift: s } => {
                let res_domain = get_domain(d, env);
                let scale = (d_sub as usize) / (d as usize);
                EvalResult::init_(
                    (d, res_domain),
                    |i| evals.evals[(scale * i + (d_sub as usize) * s) % evals.evals.len()])
            }
        }
    }

    fn evaluations_<'a>(&self, d: Domain, env: & Environment<'a, F>) -> EvalResult<'a, F> {
        match self {
            Expr::ZkPolynomial =>
                EvalResult::SubEvals { 
                    domain: Domain::D8,
                    shift: 0,
                    evals: env.zk_polynomial
                },
            Expr::Constant(x) => EvalResult::Constant(*x),
            Expr::UnnormalizedLagrangeBasis(i) =>
                EvalResult::Evals {
                    domain: d,
                    evals: unnormalized_lagrange_evals(env.l0_1, *i, d, env)
                },
            Expr::Cell(Variable { col, row }) => {
                let evals : &'a Evaluations<F, D<F>> = {
                    use Column::*;
                    match col {
                        LookupKindIndex(i) => &env.lookup_selectors[*i],
                        Witness(i) => &env.witness[*i],
                        Z => env.z,
                        LookupSorted(i) => &env.lookup_sorted[*i],
                        LookupAggreg => env.lookup_aggreg,
                        LookupTable => env.lookup_table,
                        Index(t) => 
                            match env.index.get(t) {
                                None => return EvalResult::Constant(F::zero()),
                                Some(e) => e
                            }
                    }
                };
                EvalResult::SubEvals { 
                    domain: Domain::D8,
                    shift: curr_or_next(*row),
                    evals
                }
            },
            Expr::Mul(e1, e2) => {
                e1.evaluations_(d, env).mul(e2.evaluations_(d, env), (d, get_domain(d, env)))
            },
            Expr::Add(e1, e2) => {
                e1.evaluations_(d, env).add(e2.evaluations_(d, env), (d, get_domain(d, env)))
            },
            Expr::Sub(e1, e2) => {
                e1.evaluations_(d, env).sub(e2.evaluations_(d, env), (d, get_domain(d, env)))
            },
        }
    }
}

pub struct Linearization<F> {
    pub constant_term: Expr<F>,
    pub index_terms: Vec<(Column, Expr<F>)>
}

impl<C> Expr<C> {
    pub fn constant(c: C) -> Expr<C> {
        Expr::Constant(c)
    }
}

impl<F: FftField> Expr<F> {
    fn monomials(&self) -> HashMap<Vec<Variable>, Expr<F>> {
        let sing = |v: Vec<Variable>, c: Expr<F>| {
            let mut h = HashMap::new();
            h.insert(v, c);
            h
        };
        let constant = |e : Expr<F>| sing(vec![], e);
        use Expr::*;
        match self {
            UnnormalizedLagrangeBasis(i) => constant(UnnormalizedLagrangeBasis(*i)),
            ZkPolynomial => constant(ZkPolynomial),
            Constant(c) => constant(Constant(*c)),
            Cell(var) => sing(vec![*var], Constant(F::one())),
            Add(e1, e2) => {
                let mut res = e1.monomials();
                for (m, c) in e2.monomials() {
                    let v = res.entry(m).or_insert(0.into());
                    *v = v.clone() + c;
                }
                res
            },
            Sub(e1, e2) => {
                let mut res = e1.monomials();
                for (m, c) in e2.monomials() {
                    let v = res.entry(m).or_insert(0.into());
                    *v = v.clone() - c;
                }
                res
            },
            Mul(e1, e2) => {
                let e1 = e1.monomials();
                let e2 = e2.monomials();
                let mut res : HashMap<_, Expr<F>> = HashMap::new();
                for (m1, c1) in e1.iter() {
                    for (m2, c2) in e2.iter() {
                        let mut m = m1.clone();
                        m.extend(m2);
                        m.sort();
                        let c1c2 = c1.clone() * c2.clone();
                        let v = res.entry(m).or_insert(0.into());
                        *v = v.clone() + c1c2;
                    }
                }
                res
            }
        }
    }

    pub fn linearize(&self, evaluated: HashSet<Column>) -> Result<Linearization<F>, &str> {
        let mut res : HashMap<Column, Expr<F>> = HashMap::new();
        let mut constant_term : Expr<F> = 0.into();
        for (m, c) in self.monomials() {
            let (evaluated, mut unevaluated) : (Vec<_>, _) = m.into_iter().partition(|v| evaluated.contains(&v.col));
            let c = evaluated.into_iter().fold(c, |acc, v| acc * Expr::Cell(v));
            if unevaluated.len() == 0 {
                constant_term = constant_term + c;
            } else if unevaluated.len() == 1 {
                let var = unevaluated.remove(0);
                match var.row {
                    Next => return Err("Linearization failed (needed polynomial value at \"next\" row)"),
                    Curr => {
                        let v = res.entry(var.col).or_insert(0.into());
                        *v = v.clone() + c;
                    }
                }
            }
            else {
                return Err("Linearization failed");
            }
        }
        Ok(Linearization { constant_term, index_terms: res.into_iter().collect() })
    }
}

pub type E<F> = Expr<ConstantExpr<F>>;
