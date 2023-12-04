use super::{
    expressions::{Degree, ExtendedFoldingColumn, FoldingExp},
    FoldingConfig,
};
use std::collections::{BTreeMap, HashMap};

///returns the constraints converted into degree 2 or less and the extra contraints added in the process
pub(crate) fn quadricization<C: FoldingConfig>(
    constraints: Vec<FoldingExp<C>>,
) -> (Vec<FoldingExp<C>>, Vec<FoldingExp<C>>) {
    let mut recorder = ExpRecorder::new();
    let original_constraints = constraints
        .into_iter()
        .map(|exp| lower_degree_to_2(exp, &mut recorder))
        .collect();
    let extra_constraints = recorder.into_constraints();
    (original_constraints, extra_constraints)
}

///records expressions that have been extracted into an extra column
struct ExpRecorder<C: FoldingConfig> {
    recorded_exprs: HashMap<FoldingExp<C>, usize>,
    next: usize,
}

impl<C: FoldingConfig> ExpRecorder<C> {
    fn new() -> Self {
        Self {
            recorded_exprs: Default::default(),
            next: 0,
        }
    }
    fn get_id(&mut self, exp: FoldingExp<C>) -> usize {
        *self.recorded_exprs.entry(exp).or_insert_with(|| {
            let id = self.next;
            self.next += 1;
            id
        })
    }
    fn into_constraints(self) -> Vec<FoldingExp<C>> {
        let ExpRecorder { recorded_exprs, .. } = self;
        let mut new_constraints = BTreeMap::new();
        for (exp, id) in recorded_exprs.into_iter() {
            let left = FoldingExp::Cell(ExtendedFoldingColumn::WitnessExtended(id));
            // let left = Box::new(extended(id));
            // let constraint = Expr::<C, ColumnExtended<Col>>::BinOp(Op2::Sub, left, Box::new(exp));
            let constraint = FoldingExp::Sub(Box::new(left), Box::new(exp));
            new_constraints.insert(id, constraint);
        }
        new_constraints.into_values().collect()
    }
}
fn unbounded_degree<C: FoldingConfig>(exp: &FoldingExp<C>) -> usize {
    match exp {
        e @ FoldingExp::Cell(_) => match e.folding_degree() {
            Degree::Zero => 0,
            Degree::One => 1,
            Degree::Two => 2,
        },
        FoldingExp::Double(exp) => unbounded_degree(exp),
        FoldingExp::Square(exp) => unbounded_degree(exp) * 2,
        FoldingExp::Add(e1, e2) | FoldingExp::Sub(e1, e2) => {
            std::cmp::max(unbounded_degree(e1), unbounded_degree(e2))
        }
        FoldingExp::Mul(e1, e2) => unbounded_degree(e1) + unbounded_degree(e2),
    }
}
fn lower_degree_to_1<C: FoldingConfig>(
    exp: FoldingExp<C>,
    rec: &mut ExpRecorder<C>,
) -> FoldingExp<C> {
    let degree = unbounded_degree(&exp);
    match degree {
        1 => {
            return exp;
        }
        _ => {
            let exp = lower_degree_to_2(exp, rec);
            let id = rec.get_id(exp);
            FoldingExp::Cell(ExtendedFoldingColumn::WitnessExtended(id))
        }
    }
}

fn lower_degree_to_2<C: FoldingConfig>(
    exp: FoldingExp<C>,
    rec: &mut ExpRecorder<C>,
) -> FoldingExp<C> {
    use FoldingExp::*;
    let degree = unbounded_degree(&exp);
    if degree <= 2 {
        return exp;
    }

    match exp {
        FoldingExp::Cell(_) => panic!("a column shouldn't be above degree 1"),
        FoldingExp::Double(exp) => Double(Box::new(lower_degree_to_2(*exp, rec))),
        FoldingExp::Square(exp) => Square(Box::new(lower_degree_to_1(*exp, rec))),
        FoldingExp::Add(e1, e2) => {
            let e1 = lower_degree_to_2(*e1, rec);
            let e2 = lower_degree_to_2(*e2, rec);
            Add(Box::new(e1), Box::new(e2))
        }
        FoldingExp::Sub(e1, e2) => {
            let e1 = lower_degree_to_2(*e1, rec);
            let e2 = lower_degree_to_2(*e2, rec);
            Sub(Box::new(e1), Box::new(e2))
        }
        FoldingExp::Mul(e1, e2) => {
            let d1 = unbounded_degree(&e1);
            let d2 = unbounded_degree(&e2);
            assert_eq!(degree, d1 + d2);
            let (e1, e2) = (*e1, *e2);
            let (e1, e2) = match (d1, d2) {
                (0, _) => (e1, lower_degree_to_2(e2, rec)),
                (_, 0) => (lower_degree_to_2(e1, rec), e2),
                (_, _) => (lower_degree_to_1(e1, rec), lower_degree_to_1(e2, rec)),
            };
            Mul(Box::new(e1), Box::new(e2))
        }
    }
}
