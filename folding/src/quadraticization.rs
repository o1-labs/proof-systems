//! A library to reduce constraints into degree 2.
// TODO: more documentation

use crate::{
    columns::ExtendedFoldingColumn,
    error_term::{eval_sided, ExtendedEnv, Side},
    expressions::{Degree, FoldingExp},
    FoldingConfig,
};
use std::collections::{BTreeMap, HashMap, VecDeque};

pub struct Quadraticized<C: FoldingConfig> {
    pub original_constraints: Vec<FoldingExp<C>>,
    pub extra_constraints: Vec<FoldingExp<C>>,
    pub extended_witness_generator: ExtendedWitnessGenerator<C>,
}

/// Returns the constraints converted into degree 2 or less and the extra
/// constraints added in the process
pub fn quadraticize<C: FoldingConfig>(
    constraints: Vec<FoldingExp<C>>,
) -> (Quadraticized<C>, usize) {
    let mut recorder = ExpRecorder::new();
    let original_constraints = constraints
        .into_iter()
        .map(|exp| lower_degree_to_2(exp, &mut recorder))
        .collect();
    let added_columns = recorder.next;
    let (extra_constraints, exprs) = recorder.into_constraints();
    (
        Quadraticized {
            original_constraints,
            extra_constraints,
            extended_witness_generator: ExtendedWitnessGenerator { exprs },
        },
        added_columns,
    )
}

/// Records expressions that have been extracted into an extra column
struct ExpRecorder<C: FoldingConfig> {
    recorded_exprs: HashMap<FoldingExp<C>, usize>,
    pub(crate) next: usize,
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

    #[allow(clippy::type_complexity)]
    fn into_constraints(self) -> (Vec<FoldingExp<C>>, VecDeque<(usize, FoldingExp<C>)>) {
        let ExpRecorder { recorded_exprs, .. } = self;
        let mut witness_generator = VecDeque::with_capacity(recorded_exprs.len());
        let mut new_constraints = BTreeMap::new();
        for (exp, id) in recorded_exprs.into_iter() {
            let left = FoldingExp::Atom(ExtendedFoldingColumn::WitnessExtended(id));
            let constraint = FoldingExp::Sub(Box::new(left), Box::new(exp.clone()));
            new_constraints.insert(id, constraint);
            witness_generator.push_front((id, exp));
        }
        (new_constraints.into_values().collect(), witness_generator)
    }
}

impl<C: FoldingConfig> FoldingExp<C> {
    fn degree(&self) -> usize {
        match self {
            e @ FoldingExp::Atom(_) => match e.folding_degree() {
                Degree::Zero => 0,
                Degree::One => 1,
                Degree::Two => 2,
            },
            FoldingExp::Double(exp) => exp.degree(),
            FoldingExp::Square(exp) => exp.degree() * 2,
            FoldingExp::Add(e1, e2) | FoldingExp::Sub(e1, e2) => {
                core::cmp::max(e1.degree(), e2.degree())
            }
            FoldingExp::Mul(e1, e2) => e1.degree() + e2.degree(),
            FoldingExp::Pow(e, i) => e.degree() * (*i as usize),
        }
    }
}

fn lower_degree_to_1<C: FoldingConfig>(
    exp: FoldingExp<C>,
    rec: &mut ExpRecorder<C>,
) -> FoldingExp<C> {
    let degree = exp.degree();
    match degree {
        0 => exp,
        1 => exp,
        _ => match exp {
            FoldingExp::Add(e1, e2) => FoldingExp::Add(
                Box::new(lower_degree_to_1(*e1, rec)),
                Box::new(lower_degree_to_1(*e2, rec)),
            ),
            FoldingExp::Sub(e1, e2) => FoldingExp::Sub(
                Box::new(lower_degree_to_1(*e1, rec)),
                Box::new(lower_degree_to_1(*e2, rec)),
            ),
            e @ FoldingExp::Square(_) | e @ FoldingExp::Mul(_, _) => {
                let exp = lower_degree_to_2(e, rec);
                let id = rec.get_id(exp);
                FoldingExp::Atom(ExtendedFoldingColumn::WitnessExtended(id))
            }
            FoldingExp::Double(exp) => FoldingExp::Double(Box::new(lower_degree_to_1(*exp, rec))),
            _ => todo!(),
        },
    }
}

fn lower_degree_to_2<C: FoldingConfig>(
    exp: FoldingExp<C>,
    rec: &mut ExpRecorder<C>,
) -> FoldingExp<C> {
    use FoldingExp::*;
    let degree = exp.degree();
    if degree <= 2 {
        return exp;
    }

    match exp {
        FoldingExp::Atom(_) => panic!("a column shouldn't be above degree 1"),
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
            let d1 = e1.degree();
            let d2 = e2.degree();
            assert_eq!(degree, d1 + d2);
            let (e1, e2) = (*e1, *e2);
            let (e1, e2) = match (d1, d2) {
                (0, _) => (e1, lower_degree_to_2(e2, rec)),
                (_, 0) => (lower_degree_to_2(e1, rec), e2),
                (_, _) => (lower_degree_to_1(e1, rec), lower_degree_to_1(e2, rec)),
            };
            Mul(Box::new(e1), Box::new(e2))
        }
        exp @ FoldingExp::Pow(_, 0) => exp,
        FoldingExp::Pow(e, 1) => lower_degree_to_2(*e, rec),
        FoldingExp::Pow(e, 2) => FoldingExp::Pow(Box::new(lower_degree_to_1(*e, rec)), 2),
        FoldingExp::Pow(e, i) => {
            let e = lower_degree_to_1(*e, rec);
            let mut acc = e.clone();
            for _ in 1..i - 1 {
                acc = lower_degree_to_1(FoldingExp::Mul(Box::new(e.clone()), Box::new(acc)), rec);
            }
            FoldingExp::Mul(Box::new(e.clone()), Box::new(acc))
        }
    }
}

pub struct ExtendedWitnessGenerator<C: FoldingConfig> {
    exprs: VecDeque<(usize, FoldingExp<C>)>,
}

impl<C: FoldingConfig> ExtendedWitnessGenerator<C> {
    pub(crate) fn compute_extended_witness(
        &self,
        mut env: ExtendedEnv<C>,
        side: Side,
    ) -> ExtendedEnv<C> {
        if env.needs_extension(side) {
            let mut pending = self.exprs.clone();

            while let Some((i, exp)) = pending.pop_front() {
                if check_evaluable(&exp, &env, side) {
                    let evals = eval_sided(&exp, &env, side).unwrap();
                    env.add_witness_evals(i, evals, side);
                } else {
                    pending.push_back((i, exp))
                }
            }
        }

        env
    }
}

/// Checks if the expression can be evaluated in the current environment
fn check_evaluable<C: FoldingConfig>(
    exp: &FoldingExp<C>,
    env: &ExtendedEnv<C>,
    side: Side,
) -> bool {
    match exp {
        FoldingExp::Atom(col) => env.col_try(col, side),
        FoldingExp::Double(e) | FoldingExp::Square(e) => check_evaluable(e, env, side),
        FoldingExp::Add(e1, e2) | FoldingExp::Sub(e1, e2) | FoldingExp::Mul(e1, e2) => {
            check_evaluable(e1, env, side) && check_evaluable(e2, env, side)
        }
        FoldingExp::Pow(e, _) => check_evaluable(e, env, side),
    }
}
