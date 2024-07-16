use ark_ff::Field;
use kimchi::circuits::{
    expr::{Expr, ExprInner, Variable},
    gate::CurrOrNext,
};

use crate::{columns::E, MAX_DEGREE};

use super::{columns::Column, interpreter::InterpreterEnv};

pub struct Env<Fp: Field> {
    pub idx_var: usize,
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

    fn allocate(&mut self) -> Self::Position {
        let pos = Column::X(self.idx_var);
        self.idx_var += 1;
        pos
    }

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

    fn assert_zero(&mut self, x: Self::Variable) {
        self.add_constraint(x);
    }

    fn assert_equal(&mut self, x: Self::Variable, y: Self::Variable) {
        self.add_constraint(x - y);
    }

    fn square(&mut self, col: Self::Position, x: Self::Variable) -> Self::Variable {
        let v = Expr::Atom(ExprInner::Cell(Variable {
            col,
            row: CurrOrNext::Curr,
        }));
        let x = x.square();
        self.add_constraint(x - v.clone());
        v
    }

    // This is witness-only. We simply return the corresponding expression to
    // use later in constraints
    fn fetch_input(&mut self, res: Self::Position) -> Self::Variable {
        Expr::Atom(ExprInner::Cell(Variable {
            col: res,
            row: CurrOrNext::Curr,
        }))
    }

    fn reset(&mut self) {
        self.idx_var = 0;
    }
}
