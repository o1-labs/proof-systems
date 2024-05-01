/// Implement a library to represent expressions/multivariate polynomials that
/// can be used with folding schemes like
/// [Nova](https://eprint.iacr.org/2021/370).
/// We do enforce expressions to be degree `2` maximum to apply our folding
/// scheme.
/// Before folding, we do suppose that each expression has been reduced to
/// degree `2` using [quadraticization].
use crate::{
    quadraticization::{quadraticize, ExtendedWitnessGenerator, Quadraticized},
    FoldingConfig, ScalarField,
};
use ark_ec::AffineCurve;
use ark_ff::One;
use itertools::Itertools;
use kimchi::circuits::{
    expr::{ChallengeTerm, ConstantExprInner, ConstantTerm, ExprInner, Op2, Operations, Variable},
    gate::CurrOrNext,
};
use num_traits::Zero;

pub trait FoldingColumnTrait: Copy + Clone {
    fn is_witness(&self) -> bool;

    /// TODO: why witnesses are degree 1, otherwise 0?
    fn degree(&self) -> Degree {
        match self.is_witness() {
            true => Degree::One,
            false => Degree::Zero,
        }
    }
}

/// Represents the types of additional columns that the folding scheme needs
/// while relaxing an expression.
/// It is parametrized by a configuration for the folding scheme, described in
/// the trait [FoldingConfig]. For instance, the configuration describes the
/// initial columns of the circuit, the challenges and the underlying field.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum ExtendedFoldingColumn<C: FoldingConfig> {
    Inner(Variable<C::Column>),
    /// For the extra columns added by quadraticization
    WitnessExtended(usize),
    /// The error term introduced in the "relaxed" instance.
    Error,
    UnnormalizedLagrangeBasis(usize),
    Constant(<C::Curve as AffineCurve>::ScalarField),
    /// A challenge used by the PIOP or the folding scheme.
    Challenge(C::Challenge),
    /// A list of randomizer to combine expressions
    Alpha(usize),
    /// A "virtual" selector that can be used to activate/deactivate expressions
    /// while folding/accumulating multiple expressions.
    Selector(C::S),
}

#[derive(Clone, PartialEq, Debug)]
pub enum FoldingCompatibleExprInner<C: FoldingConfig> {
    Constant(<C::Curve as AffineCurve>::ScalarField),
    Challenge(C::Challenge),
    Cell(Variable<C::Column>),
    VanishesOnZeroKnowledgeAndPreviousRows,
    /// UnnormalizedLagrangeBasis(i) is
    /// (x^n - 1) / (x - omega^i)
    UnnormalizedLagrangeBasis(usize),
    ///extra nodes created by folding, should not be passed to folding
    Extensions(ExpExtension<C>),
}

/// Designed for easy translation to and from most Expr
#[derive(Clone, PartialEq, Debug)]
pub enum FoldingCompatibleExpr<C: FoldingConfig> {
    Atom(FoldingCompatibleExprInner<C>),
    Double(Box<Self>),
    Square(Box<Self>),
    BinOp(Op2, Box<Self>, Box<Self>),
    Pow(Box<Self>, u64),
}

impl<C: FoldingConfig> ToString for FoldingCompatibleExpr<C> {
    fn to_string(&self) -> String {
        match self {
            FoldingCompatibleExpr::Atom(c) => match c {
                FoldingCompatibleExprInner::Constant(c) => {
                    let c = if c.is_zero() {
                        "0".to_string()
                    } else {
                        c.to_string()
                    };
                    c.to_string()
                }
                FoldingCompatibleExprInner::Challenge(c) => {
                    format!("{:?}", c)
                }
                FoldingCompatibleExprInner::Cell(cell) => {
                    let Variable { col, row } = cell;
                    let next = match row {
                        CurrOrNext::Curr => "",
                        CurrOrNext::Next => " * ω",
                    };
                    format!("Col({:?}){}", col, next)
                }
                FoldingCompatibleExprInner::VanishesOnZeroKnowledgeAndPreviousRows => todo!(),
                FoldingCompatibleExprInner::UnnormalizedLagrangeBasis(_) => todo!(),
                FoldingCompatibleExprInner::Extensions(e) => match e {
                    ExpExtension::U => "U".to_string(),
                    ExpExtension::Error => "E".to_string(),
                    ExpExtension::ExtendedWitness(i) => {
                        format!("ExWit({})", i)
                    }
                    ExpExtension::Alpha(i) => format!("α_{i}"),
                    ExpExtension::Selector(s) => format!("Selec({:?})", s),
                },
            },
            FoldingCompatibleExpr::Double(e) => {
                format!("2 {}", e.to_string())
            }
            FoldingCompatibleExpr::Square(e) => {
                format!("{} ^ 2", e.to_string())
            }
            FoldingCompatibleExpr::BinOp(op, e1, e2) => {
                let op_char = match op {
                    Op2::Add => "+",
                    Op2::Mul => "*",
                    Op2::Sub => "-",
                };
                match op {
                    Op2::Add | Op2::Sub => {
                        format!("{} {} {}", e1.to_string(), op_char, e2.to_string())
                    }
                    Op2::Mul => {
                        format!("({}) {} ({})", e1.to_string(), op_char, e2.to_string())
                    }
                }
            }
            FoldingCompatibleExpr::Pow(_, _) => todo!(),
        }
    }
}

/// Extra expressions that can be created by folding
#[derive(Clone, Debug, PartialEq)]
pub enum ExpExtension<C: FoldingConfig> {
    U,
    Error,
    // from quadraticization
    ExtendedWitness(usize),
    Alpha(usize),
    // in case of using decomposable folding
    Selector(C::S),
}

/// Internal expression used for folding.
/// A "folding" expression is a multivariate polynomial like defined in
/// [kimchi::circuits::expr] with the following differences:
/// - No constructors related to zero-knowledge or lagrange basis (i.e. no
/// constructors related to the PIOP)
/// - The variables includes a set of columns that describes the initial circuit
/// shape, with additional columns strictly related to the folding scheme (error
/// term, etc).
// TODO: renamed in "RelaxedExpression"?
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum FoldingExp<C: FoldingConfig> {
    Atom(ExtendedFoldingColumn<C>),
    Pow(Box<Self>, u64),
    Add(Box<Self>, Box<Self>),
    Mul(Box<Self>, Box<Self>),
    Sub(Box<Self>, Box<Self>),
    Double(Box<Self>),
    Square(Box<Self>),
}

impl<C: FoldingConfig> std::ops::Add for FoldingExp<C> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        Self::Add(Box::new(self), Box::new(rhs))
    }
}

impl<C: FoldingConfig> std::ops::Sub for FoldingExp<C> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self {
        Self::Sub(Box::new(self), Box::new(rhs))
    }
}

impl<C: FoldingConfig> std::ops::Mul for FoldingExp<C> {
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

impl<C: FoldingConfig> FoldingCompatibleExpr<C> {
    pub(crate) fn simplify(self) -> FoldingExp<C> {
        type Ex<C> = ExtendedFoldingColumn<C>;
        use FoldingExp::*;
        match self {
            FoldingCompatibleExpr::Atom(atom) => match atom {
                FoldingCompatibleExprInner::Constant(c) => Atom(ExtendedFoldingColumn::Constant(c)),
                FoldingCompatibleExprInner::Challenge(c) => {
                    Atom(ExtendedFoldingColumn::Challenge(c))
                }
                FoldingCompatibleExprInner::Cell(col) => Atom(ExtendedFoldingColumn::Inner(col)),
                FoldingCompatibleExprInner::VanishesOnZeroKnowledgeAndPreviousRows => todo!(),
                FoldingCompatibleExprInner::UnnormalizedLagrangeBasis(i) => {
                    Atom(Ex::UnnormalizedLagrangeBasis(i))
                }
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
            FoldingCompatibleExpr::BinOp(op, e1, e2) => {
                let e1 = Box::new(e1.simplify());
                let e2 = Box::new(e2.simplify());
                match op {
                    Op2::Add => Add(e1, e2),
                    Op2::Mul => Mul(e1, e2),
                    Op2::Sub => Sub(e1, e2),
                }
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
}

/// Describe the degree of a constraint.
/// Only degree up to `2` is supported.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Degree {
    Zero,
    One,
    Two,
}

impl<C: FoldingConfig> FoldingExp<C> {
    pub(super) fn folding_degree(&self) -> Degree {
        use Degree::*;
        match self {
            FoldingExp::Atom(ex_col) => match ex_col {
                ExtendedFoldingColumn::Inner(col) => col.col.degree(),
                ExtendedFoldingColumn::WitnessExtended(_) => One,
                ExtendedFoldingColumn::Error => One,
                ExtendedFoldingColumn::UnnormalizedLagrangeBasis(_) => Zero,
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
                ExtendedFoldingColumn::UnnormalizedLagrangeBasis(i) => {
                    Atom(UnnormalizedLagrangeBasis(i))
                }
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
                BinOp(Op2::Add, e1, e2)
            }
            FoldingExp::Sub(e1, e2) => {
                let e1 = Box::new(e1.into_compatible());
                let e2 = Box::new(e2.into_compatible());
                BinOp(Op2::Sub, e1, e2)
            }
            FoldingExp::Mul(e1, e2) => {
                let e1 = Box::new(e1.into_compatible());
                let e2 = Box::new(e2.into_compatible());
                BinOp(Op2::Mul, e1, e2)
            }
            // TODO: Replace with `Pow`
            FoldingExp::Pow(_, 0) => Atom(Constant(<C::Curve as AffineCurve>::ScalarField::one())),
            FoldingExp::Pow(e, 1) => e.into_compatible(),
            FoldingExp::Pow(e, i) => {
                let e = e.into_compatible();
                let mut acc = e.clone();
                for _ in 1..i {
                    acc = BinOp(Op2::Mul, Box::new(e.clone()), Box::new(acc))
                }
                acc
            }
        }
    }
}

impl std::ops::Add for Degree {
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

impl std::ops::Mul for &Degree {
    type Output = Degree;

    fn mul(self, rhs: Self) -> Self::Output {
        use Degree::*;
        match (self, rhs) {
            (Zero, other) | (other, Zero) => *other,
            (One, One) => Two,
            _ => panic!("degree over 2"),
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Sign {
    Pos,
    Neg,
}

impl std::ops::Neg for Sign {
    type Output = Self;

    fn neg(self) -> Self {
        match self {
            Sign::Pos => Sign::Neg,
            Sign::Neg => Sign::Pos,
        }
    }
}

#[derive(Clone, Debug)]
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

impl<C: FoldingConfig> std::ops::Mul for &Term<C> {
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

impl<C: FoldingConfig> std::ops::Neg for Term<C> {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Term {
            sign: -self.sign,
            ..self
        }
    }
}

/// A simplified expression with all terms separated by degree
#[derive(Clone, Debug)]
pub struct IntegratedFoldingExpr<C: FoldingConfig> {
    // (exp,sign,alpha)
    pub(super) degree_0: Vec<(FoldingExp<C>, Sign, usize)>,
    pub(super) degree_1: Vec<(FoldingExp<C>, Sign, usize)>,
    pub(super) degree_2: Vec<(FoldingExp<C>, Sign, usize)>,
}

impl<C: FoldingConfig> Default for IntegratedFoldingExpr<C> {
    fn default() -> Self {
        Self {
            degree_0: vec![],
            degree_1: vec![],
            degree_2: vec![],
        }
    }
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
        let d0 = Box::new(BinOp(Op2::Mul, Box::new(d0), u2()));
        let d1 = Box::new(BinOp(Op2::Mul, Box::new(d1), u()));
        let d2 = Box::new(d2);
        let exp = Box::new(BinOp(Op2::Add, d0, d1));
        let exp = Box::new(BinOp(Op2::Add, exp, d2));
        BinOp(
            Op2::Add,
            exp,
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
                    <C::Curve as AffineCurve>::ScalarField::one(),
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

pub(crate) fn folding_expression<C: FoldingConfig>(
    exps: Vec<FoldingCompatibleExpr<C>>,
) -> (IntegratedFoldingExpr<C>, ExtendedWitnessGenerator<C>) {
    let simplified_expressions = exps.into_iter().map(|exp| exp.simplify()).collect_vec();
    let Quadraticized {
        original_constraints: expressions,
        extra_constraints: extra_expressions,
        extended_witness_generator,
    } = quadraticize(simplified_expressions);
    let mut terms = vec![];
    let mut alpha = 0;
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
    (integrated, extended_witness_generator)
}

impl<F, Config: FoldingConfig> From<ConstantExprInner<F>> for FoldingCompatibleExprInner<Config>
where
    Config::Curve: AffineCurve<ScalarField = F>,
    Config::Challenge: From<ChallengeTerm>,
{
    fn from(expr: ConstantExprInner<F>) -> Self {
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

impl<F, Col, Config: FoldingConfig<Column = Col>> From<ExprInner<ConstantExprInner<F>, Col>>
    for FoldingCompatibleExprInner<Config>
where
    Config::Curve: AffineCurve<ScalarField = F>,
    Config::Challenge: From<ChallengeTerm>,
{
    fn from(expr: ExprInner<ConstantExprInner<F>, Col>) -> Self {
        match expr {
            ExprInner::Constant(cexpr) => cexpr.into(),
            ExprInner::Cell(col) => FoldingCompatibleExprInner::Cell(col),
            ExprInner::VanishesOnZeroKnowledgeAndPreviousRows => {
                FoldingCompatibleExprInner::VanishesOnZeroKnowledgeAndPreviousRows
            }
            ExprInner::UnnormalizedLagrangeBasis(i) => {
                FoldingCompatibleExprInner::UnnormalizedLagrangeBasis(i.offset as usize)
            }
        }
    }
}

impl<F, Col, Config: FoldingConfig<Column = Col>>
    From<Operations<ExprInner<ConstantExprInner<F>, Col>>> for FoldingCompatibleExpr<Config>
where
    Config::Curve: AffineCurve<ScalarField = F>,
    Config::Challenge: From<ChallengeTerm>,
{
    fn from(expr: Operations<ExprInner<ConstantExprInner<F>, Col>>) -> Self {
        match expr {
            Operations::Atom(inner) => FoldingCompatibleExpr::Atom(inner.into()),
            Operations::Add(x, y) => {
                FoldingCompatibleExpr::BinOp(Op2::Add, Box::new((*x).into()), Box::new((*y).into()))
            }
            Operations::Mul(x, y) => {
                FoldingCompatibleExpr::BinOp(Op2::Mul, Box::new((*x).into()), Box::new((*y).into()))
            }
            Operations::Sub(x, y) => {
                FoldingCompatibleExpr::BinOp(Op2::Sub, Box::new((*x).into()), Box::new((*y).into()))
            }
            Operations::Double(x) => FoldingCompatibleExpr::Double(Box::new((*x).into())),
            Operations::Square(x) => FoldingCompatibleExpr::Square(Box::new((*x).into())),
            Operations::Pow(e, p) => FoldingCompatibleExpr::Pow(Box::new((*e).into()), p),
            _ => panic!("Operation not supported in folding expressions"),
        }
    }
}
