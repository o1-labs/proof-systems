use crate::{
    circuits::{expr::Op2, gate::CurrOrNext},
    folding::{
        quadricization::{quadricization, ExtendedWitnessGenerator},
        Fi, FoldingConfig,
    },
};
use ark_ec::AffineCurve;
use itertools::Itertools;
use num_traits::Zero;

pub trait FoldingColumnTrait: Copy + Clone {
    fn is_witness(&self) -> bool;
    fn degree(&self) -> Degree {
        match self.is_witness() {
            true => Degree::One,
            false => Degree::Zero,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum ExtendedFoldingColumn<C: FoldingConfig> {
    Inner(C::Column),
    ///for the extra columns added by quadricization
    #[allow(dead_code)]
    WitnessExtended(usize),
    Error,
    ///basically X, to allow accesing the next row
    Shift,
    UnnormalizedLagrangeBasis(usize),
    Constant(<C::Curve as AffineCurve>::ScalarField),
    Challenge(C::Challenge),
    Alpha(usize),
}

pub struct Var<C> {
    pub col: C,
    pub row: CurrOrNext,
}

///designed for easy translation to and from most Expr
pub enum FoldingCompatibleExpr<C: FoldingConfig> {
    Constant(<C::Curve as AffineCurve>::ScalarField),
    Challenge(C::Challenge),
    Cell(Var<C::Column>),
    Double(Box<Self>),
    Square(Box<Self>),
    BinOp(Op2, Box<Self>, Box<Self>),
    VanishesOnZeroKnowledgeAndPreviousRows,
    /// UnnormalizedLagrangeBasis(i) is
    /// (x^n - 1) / (x - omega^i)
    UnnormalizedLagrangeBasis(usize),
    Pow(Box<Self>, u64),
    ///extra nodes created by folding, should not be passed to folding
    Extensions(ExpExtension),
}

/// Extra expressions that can be created by folding
pub enum ExpExtension {
    U,
    Error,
    //from quadricization
    ExtendedWitness(usize),
    Alpha(usize),
    Shift,
}

///Internal expression used for folding, simplified for that purpose
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum FoldingExp<C: FoldingConfig> {
    Cell(ExtendedFoldingColumn<C>),
    Double(Box<FoldingExp<C>>),
    Square(Box<FoldingExp<C>>),
    Add(Box<FoldingExp<C>>, Box<FoldingExp<C>>),
    Sub(Box<FoldingExp<C>>, Box<FoldingExp<C>>),
    Mul(Box<FoldingExp<C>>, Box<FoldingExp<C>>),
}

impl<C: FoldingConfig> FoldingCompatibleExpr<C> {
    pub(crate) fn simplify(self) -> FoldingExp<C> {
        type Ex<C> = ExtendedFoldingColumn<C>;
        use FoldingExp::*;
        match self {
            FoldingCompatibleExpr::Constant(c) => Cell(ExtendedFoldingColumn::Constant(c)),
            FoldingCompatibleExpr::Challenge(c) => Cell(ExtendedFoldingColumn::Challenge(c)),
            FoldingCompatibleExpr::Cell(col) => {
                let Var { col, row } = col;
                let col = Cell(ExtendedFoldingColumn::Inner(col));
                match row {
                    CurrOrNext::Curr => col,
                    CurrOrNext::Next => {
                        let shift = Cell(Ex::Shift);
                        Mul(Box::new(col), Box::new(shift))
                    }
                }
            }
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
            FoldingCompatibleExpr::VanishesOnZeroKnowledgeAndPreviousRows => todo!(),
            FoldingCompatibleExpr::UnnormalizedLagrangeBasis(i) => {
                Cell(Ex::UnnormalizedLagrangeBasis(i))
            }
            FoldingCompatibleExpr::Pow(e, p) => Self::pow_to_mul(e.simplify(), p),
            FoldingCompatibleExpr::Extensions(_) => {
                panic!("this should only be created by folding itself")
            }
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

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Degree {
    Zero,
    One,
    Two,
}

impl<C: FoldingConfig> FoldingExp<C> {
    pub(super) fn folding_degree(&self) -> Degree {
        use Degree::*;
        match self {
            FoldingExp::Cell(ex_col) => match ex_col {
                ExtendedFoldingColumn::Inner(col) => col.degree(),
                ExtendedFoldingColumn::WitnessExtended(_) => One,
                ExtendedFoldingColumn::Error => One,
                ExtendedFoldingColumn::Shift => Zero,
                ExtendedFoldingColumn::UnnormalizedLagrangeBasis(_) => Zero,
                ExtendedFoldingColumn::Constant(_) => Zero,
                ExtendedFoldingColumn::Challenge(_) => One,
                ExtendedFoldingColumn::Alpha(_) => One,
            },
            FoldingExp::Double(e) => e.folding_degree(),
            FoldingExp::Square(e) => &e.folding_degree() * &e.folding_degree(),
            FoldingExp::Mul(e1, e2) => &e1.folding_degree() * &e2.folding_degree(),
            FoldingExp::Add(e1, e2) | FoldingExp::Sub(e1, e2) => {
                e1.folding_degree() + e2.folding_degree()
            }
        }
    }

    fn into_compatible(self) -> FoldingCompatibleExpr<C> {
        use FoldingCompatibleExpr::*;
        match self {
            FoldingExp::Cell(c) => match c {
                ExtendedFoldingColumn::Inner(col) => Cell(Var {
                    col,
                    row: CurrOrNext::Curr,
                }),
                ExtendedFoldingColumn::WitnessExtended(i) => {
                    Extensions(ExpExtension::ExtendedWitness(i))
                }
                ExtendedFoldingColumn::Error => Extensions(ExpExtension::Error),
                ExtendedFoldingColumn::Shift => Extensions(ExpExtension::Shift),
                ExtendedFoldingColumn::UnnormalizedLagrangeBasis(i) => UnnormalizedLagrangeBasis(i),
                ExtendedFoldingColumn::Constant(c) => Constant(c),
                ExtendedFoldingColumn::Challenge(c) => Challenge(c),
                ExtendedFoldingColumn::Alpha(i) => Extensions(ExpExtension::Alpha(i)),
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
        }
    }
}

impl std::ops::Add for Degree {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        use Degree::*;
        match (self, rhs) {
            (Zero, Zero) => Zero,
            (Zero, One) | (One, Zero) | (One, One) => One,
            (_, Two) | (Two, _) => Two,
        }
    }
}

impl std::ops::Mul for &Degree {
    type Output = Degree;

    fn mul(self, rhs: Self) -> Self::Output {
        use Degree::*;
        match (self, rhs) {
            (Zero, Zero) => Zero,
            (Zero, One) | (One, Zero) => One,
            (Zero, Two) | (One, One) | (Two, Zero) => Two,
            (One, Two) | (Two, One) | (Two, Two) => panic!("degree over 2"),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Term<C: FoldingConfig> {
    pub exp: FoldingExp<C>,
    pub sign: bool,
}

impl<C: FoldingConfig> Term<C> {
    /*fn map_exp<F>(self, f: F) -> Self
    where
        F: Fn(FoldingExp2<C>) -> FoldingExp2<C>,
    {
        let Self { exp, sign } = self;
        let exp = f(exp);
        Self { exp, sign }
    }*/
    fn wrap_exp<F>(self, f: F) -> Self
    where
        F: Fn(Box<FoldingExp<C>>) -> FoldingExp<C>,
    {
        let Self { exp, sign } = self;
        let exp = f(Box::new(exp));
        Self { exp, sign }
    }
}

impl<C: FoldingConfig> std::ops::Mul for &Term<C> {
    type Output = Term<C>;

    fn mul(self, rhs: Self) -> Self::Output {
        #[allow(clippy::suspicious_arithmetic_impl)]
        let sign = !(self.sign ^ rhs.sign);
        let exp = FoldingExp::Mul(Box::new(self.exp.clone()), Box::new(rhs.exp.clone()));
        Term { exp, sign }
    }
}

impl<C: FoldingConfig> std::ops::Neg for Term<C> {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Term {
            sign: !self.sign,
            ..self
        }
    }
}

///A simplified expression with all terms separated by degree
#[derive(Clone, Debug)]
pub struct IntegratedFoldingExpr<C: FoldingConfig> {
    //(exp,sign,alpha)
    pub(super) degree_0: Vec<(FoldingExp<C>, bool, usize)>,
    pub(super) degree_1: Vec<(FoldingExp<C>, bool, usize)>,
    pub(super) degree_2: Vec<(FoldingExp<C>, bool, usize)>,
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
    ///combines constraints into single expression
    pub fn final_expression(self) -> FoldingCompatibleExpr<C> {
        ///todo: should use powers of alpha
        use FoldingCompatibleExpr::*;
        let Self {
            degree_0,
            degree_1,
            degree_2,
        } = self;
        let [d0, d1, d2] = [degree_0, degree_1, degree_2]
            .map(|exps| {
                let init = FoldingExp::Cell(ExtendedFoldingColumn::Constant(Fi::<C>::zero()));
                exps.into_iter().fold(init, |acc, (exp, sign, alpha)| {
                    let e = if sign {
                        FoldingExp::Add(Box::new(acc), Box::new(exp))
                    } else {
                        FoldingExp::Sub(Box::new(acc), Box::new(exp))
                    };
                    FoldingExp::Mul(
                        Box::new(e),
                        Box::new(FoldingExp::Cell(ExtendedFoldingColumn::Alpha(alpha))),
                    )
                })
            })
            .map(|e| e.into_compatible());
        let u = || Box::new(Extensions(ExpExtension::U));
        let u2 = || Box::new(Square(u()));
        let d0 = Box::new(BinOp(Op2::Mul, Box::new(d0), u2()));
        let d1 = Box::new(BinOp(Op2::Mul, Box::new(d1), u()));
        let d2 = Box::new(d2);
        let exp = Box::new(BinOp(Op2::Add, d0, d1));
        let exp = Box::new(BinOp(Op2::Add, exp, d2));
        BinOp(Op2::Add, exp, Box::new(Extensions(ExpExtension::Error)))
    }
}

pub fn extract_terms<C: FoldingConfig>(exp: FoldingExp<C>) -> Box<dyn Iterator<Item = Term<C>>> {
    use FoldingExp::*;
    let exps: Box<dyn Iterator<Item = Term<C>>> = match exp {
        exp @ Cell(_) => Box::new([Term { exp, sign: true }].into_iter()),
        Double(exp) => Box::new(extract_terms(*exp).map(|t| t.wrap_exp(Double))),
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
    };
    exps
}

pub fn folding_expression<C: FoldingConfig>(
    exps: Vec<FoldingCompatibleExpr<C>>,
) -> (IntegratedFoldingExpr<C>, ExtendedWitnessGenerator<C>) {
    // let simplied = simplify_expression(exp, flag_resolver);
    let simplified_expressions = exps.into_iter().map(|exp| exp.simplify()).collect_vec();
    let (expressions, extra_expressions, extenden_witness_generator) =
        quadricization(simplified_expressions);
    let mut terms = vec![];
    // let terms = extract_terms2(expressions);
    println!("constraints");
    let mut alpha = 0;
    for exp in expressions.into_iter() {
        terms.extend(extract_terms(exp).map(|term| (term, alpha)));
        alpha += 1;
    }
    println!("extra");
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
    (integrated, extenden_witness_generator)
}
