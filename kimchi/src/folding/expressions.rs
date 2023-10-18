use super::{CacheId, GateType};
use crate::circuits::{
    expr::{Column, Expr, FeatureFlag, Op2, Variable},
    gate::CurrOrNext,
};

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FoldingColumn {
    Witness(usize),
    ///for the extra columns added by quadricization
    #[allow(dead_code)]
    WitnessExtended(usize),
    Index(GateType),
    Coefficient(usize),
    ///basically X, to allow accesing the next row
    Shift,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
///A simplified expression to be use in folding
pub enum FoldingExp<C> {
    Constant(C),
    Cell(FoldingColumn),
    Double(Box<FoldingExp<C>>),
    Square(Box<FoldingExp<C>>),
    Add(Box<FoldingExp<C>>, Box<FoldingExp<C>>),
    Sub(Box<FoldingExp<C>>, Box<FoldingExp<C>>),
    Mul(Box<FoldingExp<C>>, Box<FoldingExp<C>>),
    UnnormalizedLagrangeBasis(i32),
    Cache(CacheId, Box<FoldingExp<C>>),
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Degree {
    Zero,
    One,
    Two,
}
impl<C> FoldingExp<C> {
    pub(super) fn degree(&self) -> Degree {
        use Degree::*;
        match self {
            FoldingExp::Constant(_) => Zero,
            FoldingExp::Cell(col) => match col {
                FoldingColumn::Witness(_) | FoldingColumn::WitnessExtended(_) => One,
                _ => Zero,
            },
            FoldingExp::Double(e) => e.degree(),
            FoldingExp::Square(e) => &e.degree() * &e.degree(),
            FoldingExp::Add(e1, e2) | FoldingExp::Sub(e1, e2) | FoldingExp::Mul(e1, e2) => {
                e1.degree() + e2.degree()
            }
            FoldingExp::UnnormalizedLagrangeBasis(_) => Zero,
            FoldingExp::Cache(_, e) => e.degree(),
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

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Term<C> {
    pub exp: FoldingExp<C>,
    pub sign: bool,
    pub degree: Degree,
}

impl<C> Term<C> {
    fn new(exp: FoldingExp<C>, degree: Degree) -> Self {
        Self {
            exp,
            sign: true,
            degree,
        }
    }
}
impl<C> std::ops::Neg for Term<C> {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Term {
            sign: !self.sign,
            ..self
        }
    }
}
///A simplified expression with all terms separated by degree
pub struct IntegratedFoldingExpr<C> {
    pub(super) degree_0: Vec<(FoldingExp<C>, bool)>,
    pub(super) degree_1: Vec<(FoldingExp<C>, bool)>,
    pub(super) degree_2: Vec<(FoldingExp<C>, bool)>,
}

impl<C> Default for IntegratedFoldingExpr<C> {
    fn default() -> Self {
        Self {
            degree_0: vec![],
            degree_1: vec![],
            degree_2: vec![],
        }
    }
}
// fn extract_terms<C: Clone, F>(exp: FoldingExp<C>) -> Vec<Term<C>>
pub fn extract_terms<C: Clone, F>(exp: FoldingExp<C>, terms: &mut Vec<Term<C>>, f: &F)
where
    F: Fn(Term<C>) -> Term<C>,
{
    use Degree::*;
    match exp {
        e @ FoldingExp::Constant(_) => {
            let term = f(Term::new(e, Zero));
            terms.push(term)
        }
        FoldingExp::Cell(col) => {
            let degree = match col {
                FoldingColumn::Witness(_) | FoldingColumn::WitnessExtended(_) => One,
                _ => Zero,
            };
            let exp = FoldingExp::Cell(col);
            let term = f(Term::new(exp, degree));
            terms.push(term)
        }
        FoldingExp::Double(e) => {
            let f = |t| {
                let Term { exp, sign, degree } = t;
                let exp = FoldingExp::Double(Box::new(exp));
                f(Term { exp, sign, degree })
            };
            let f: Box<dyn Fn(Term<C>) -> Term<C>> = Box::new(f);
            extract_terms(*e, terms, &f);
        }
        FoldingExp::Square(e) => {
            let mut temp = Vec::with_capacity(4);
            extract_terms(*e.clone(), &mut temp, f);
            for term in temp {
                let Term { exp, sign, degree } = term;
                let exp = Box::new(exp);
                let f = |t| {
                    let Term {
                        exp: exp2,
                        sign: sign2,
                        degree: degree2,
                    } = t;
                    let degree = &degree * &degree2;
                    let sign = sign != sign2;
                    //TODO: specialize square case
                    let exp = FoldingExp::Mul(exp.clone(), Box::new(exp2));
                    Term { exp, sign, degree }
                };
                let f: Box<dyn Fn(Term<C>) -> Term<C>> = Box::new(f);
                extract_terms(*e.clone(), terms, &f);
            }
        }
        FoldingExp::Add(e1, e2) => {
            extract_terms(*e1, terms, f);
            extract_terms(*e2, terms, f);
        }
        FoldingExp::Sub(e1, e2) => {
            extract_terms(*e1, terms, f);
            let f = |t: Term<C>| f(-t);
            let f: Box<dyn Fn(Term<C>) -> Term<C>> = Box::new(f);
            extract_terms(*e2, terms, &f);
        }
        FoldingExp::Mul(e1, e2) => {
            let mut temp = Vec::with_capacity(4);
            extract_terms(*e1, &mut temp, f);
            for term in temp {
                let Term { exp, sign, degree } = term;
                let exp = Box::new(exp);
                let f = |t| {
                    let Term {
                        exp: exp2,
                        sign: sign2,
                        degree: degree2,
                    } = t;
                    let degree = &degree * &degree2;
                    let sign = sign == sign2;
                    let exp = FoldingExp::Mul(exp.clone(), Box::new(exp2));
                    Term { exp, sign, degree }
                };
                let f: Box<dyn Fn(Term<C>) -> Term<C>> = Box::new(f);
                extract_terms(*e2.clone(), terms, &f);
            }
        }
        e @ FoldingExp::UnnormalizedLagrangeBasis(_) => {
            let term = f(Term::new(e, Zero));
            terms.push(term)
        }
        FoldingExp::Cache(id, e) => {
            let f = |t| {
                let Term { exp, sign, degree } = t;
                let exp = FoldingExp::Cache(id, Box::new(exp));
                Term { exp, sign, degree }
            };
            let f: Box<dyn Fn(Term<C>) -> Term<C>> = Box::new(f);
            extract_terms(*e, terms, &f);
        }
    }
}

///simplyfies the expression, and separates it into terms of different degree y
pub fn folding_expression<C: Copy, F: Fn(&FeatureFlag) -> bool>(
    exp: &Expr<C>,
    flag_resolver: &F,
) -> IntegratedFoldingExpr<C> {
    let simplied = simplify_expression(exp, flag_resolver);
    let mut terms = vec![];
    extract_terms(simplied, &mut terms, &|t| t);
    let mut integrated = IntegratedFoldingExpr::default();
    for term in terms.into_iter() {
        let Term { exp, sign, degree } = term;
        let t = (exp, sign);
        match degree {
            Degree::Zero => integrated.degree_0.push(t),
            Degree::One => integrated.degree_1.push(t),
            Degree::Two => integrated.degree_2.push(t),
        }
    }
    integrated
}
fn simplify_expression<C: Copy, F: Fn(&FeatureFlag) -> bool>(
    exp: &Expr<C>,
    flag_resolver: &F,
) -> FoldingExp<C> {
    match exp {
        Expr::Constant(c) => FoldingExp::Constant(*c),
        Expr::Cell(v) => {
            let Variable { col, row } = v;
            let col = match col {
                Column::Witness(i) => FoldingColumn::Witness(*i),
                Column::Index(i) => FoldingColumn::Index(*i),
                Column::Coefficient(i) => FoldingColumn::Coefficient(*i),
                _ => unreachable!(),
            };
            let cell = Box::new(FoldingExp::Cell(col));
            let shift = Box::new(FoldingExp::Cell(FoldingColumn::Shift));
            match row {
                CurrOrNext::Curr => *cell,
                CurrOrNext::Next => FoldingExp::Mul(cell, shift),
            }
        }
        //may be better to replace by mul by 2
        Expr::Double(e) => {
            let e = simplify_expression(e, flag_resolver);
            FoldingExp::Double(Box::new(e))
        }
        //may be better to replace by mul by itself
        Expr::Square(e) => {
            let e = simplify_expression(e, flag_resolver);
            FoldingExp::Square(Box::new(e))
        }
        Expr::BinOp(op, e1, e2) => {
            let e1 = Box::new(simplify_expression(e1, flag_resolver));
            let e2 = Box::new(simplify_expression(e2, flag_resolver));
            match op {
                Op2::Add => FoldingExp::Add(e1, e2),
                Op2::Sub => FoldingExp::Sub(e1, e2),
                Op2::Mul => FoldingExp::Mul(e1, e2),
            }
        }
        Expr::UnnormalizedLagrangeBasis(i) => {
            assert!(!i.zk_rows);
            FoldingExp::UnnormalizedLagrangeBasis(i.offset)
        }
        Expr::Cache(id, e) => {
            let e = simplify_expression(e, flag_resolver);
            FoldingExp::Cache(*id, Box::new(e))
        }
        Expr::IfFeature(flag, e1, e2) => {
            if flag_resolver(flag) {
                simplify_expression(e1, flag_resolver)
            } else {
                simplify_expression(e2, flag_resolver)
            }
        }
        Expr::Pow(_, _) => {
            unreachable!()
        }
        //TODO: check that this is fine
        Expr::VanishesOnZeroKnowledgeAndPreviousRows => todo!(),
    }
}
