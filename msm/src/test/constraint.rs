use crate::{
    columns::{Column, ColumnIndexer},
    expr::E,
    test::{columns::TestColumnIndexer, interpreter::TestInterpreterEnv},
};
use ark_ff::PrimeField;
use kimchi::circuits::{
    expr::{ConstantExpr, ConstantTerm, Expr, ExprInner, Variable},
    gate::CurrOrNext,
};

/// Contains constraints for just one row.
pub struct ConstraintBuilderEnv<F> {
    pub constraints: Vec<E<F>>,
}

impl<F: PrimeField> TestInterpreterEnv<F> for ConstraintBuilderEnv<F> {
    type Position = Column;

    type Variable = E<F>;

    fn empty() -> Self {
        ConstraintBuilderEnv {
            constraints: vec![],
        }
    }

    fn assert_zero(&mut self, cst: Self::Variable) {
        self.constraints.push(cst)
    }

    fn copy(&mut self, x: &Self::Variable, position: Self::Position) -> Self::Variable {
        let y = Expr::Atom(ExprInner::Cell(Variable {
            col: position,
            row: CurrOrNext::Curr,
        }));
        self.constraints.push(y.clone() - x.clone());
        y
    }

    fn constant(value: F) -> Self::Variable {
        let cst_expr_inner = ConstantExpr::from(ConstantTerm::Literal(value));
        Expr::Atom(ExprInner::Constant(cst_expr_inner))
    }

    // TODO deduplicate, remove this
    fn column_pos(ix: TestColumnIndexer) -> Self::Position {
        ix.to_column()
    }

    fn read_column(&self, ix: TestColumnIndexer) -> Self::Variable {
        Expr::Atom(ExprInner::Cell(Variable {
            col: ix.to_column(),
            row: CurrOrNext::Curr,
        }))
    }
}
