use ark_ff::Field;
use kimchi::circuits::{
    expr::{Expr, ExprInner, Variable},
    gate::CurrOrNext,
};

use crate::{columns::E, MAX_DEGREE};

use super::{columns::Column, interpreter::InterpreterEnv};

pub struct Env<Fp: Field> {
    pub constraints: Vec<E<Fp>>,
}

/// An environment to build constraints.
/// The constraint environment is mostly useful when we want to perform a Nova
/// proof.
/// The constraint environment must be instantiated only once, at the last step
/// of the computation.
impl<Fp: Field> InterpreterEnv for Env<Fp> {
    type Position = Column;

    type Variable = E<Fp>;

    fn variable(&self, column: Self::Position) -> Self::Variable {
        Expr::Atom(ExprInner::Cell(Variable {
            col: column,
            row: CurrOrNext::Curr,
        }))
    }

    fn add_constraint(&mut self, constraint: Self::Variable) {
        let degree = constraint.degree(1, 0);
        assert!(degree <= MAX_DEGREE, "degree is too high: {}. The folding scheme used currently allows constraint up to degree {}", degree, MAX_DEGREE);
        self.constraints.push(constraint);
    }
}
