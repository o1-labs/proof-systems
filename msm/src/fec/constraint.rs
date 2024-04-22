use crate::{
    columns::Column,
    expr::E,
    fec::{interpreter::FECInterpreterEnv, lookups::LookupTable},
};
use ark_ff::PrimeField;
use kimchi::circuits::{
    expr::{ConstantExpr, ConstantTerm, Expr, ExprInner, Variable},
    gate::CurrOrNext,
};
use std::marker::PhantomData;

/// Contains constraints for just one row.
pub struct ConstraintBuilderEnv<F, Ff> {
    pub constraints: Vec<E<F>>,
    pub phantom: PhantomData<Ff>,
}

impl<F: PrimeField, Ff: PrimeField> FECInterpreterEnv<F, LookupTable<Ff>>
    for ConstraintBuilderEnv<F, Ff>
{
    type Variable = E<F>;

    fn empty() -> Self {
        ConstraintBuilderEnv {
            constraints: vec![],
            phantom: PhantomData,
        }
    }

    fn assert_zero(&mut self, cst: Self::Variable) {
        self.constraints.push(cst)
    }

    fn copy(&mut self, x: &Self::Variable, position: Column) -> Self::Variable {
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

    fn read_column(&self, ix: Column) -> Self::Variable {
        Expr::Atom(ExprInner::Cell(Variable {
            col: ix,
            row: CurrOrNext::Curr,
        }))
    }

    fn lookup(&mut self, table_id: LookupTable<Ff>, value: &Self::Variable) {
        let one = ConstantExpr::from(ConstantTerm::Literal(F::one()));
        let lookup = Lookup {
            table_id,
            numerator: Expr::Atom(ExprInner::Constant(one)),
            value: vec![value.clone()],
        };
        self.lookups.entry(table_id).or_default().push(lookup);
    }

    fn range_check_abs1(&mut self, _value: &Self::Variable) {
        // FIXME unimplemented
    }

    fn range_check_ff_highest(&mut self, _value: &Self::Variable) {}

    fn range_check_15bit(&mut self, _value: &Self::Variable) {
        // FIXME unimplemented
    }

    fn range_check_abs15bit(&mut self, _value: &Self::Variable) {
        // FIXME unimplemented
    }

    fn range_check_abs4bit(&mut self, _value: &Self::Variable) {
        // FIXME unimplemented
    }
}
