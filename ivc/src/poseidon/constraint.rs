use crate::poseidon::interpreter::{Column, Params, PoseidonInterpreter};
use ark_ff::Field;
use kimchi::circuits::{
    expr::{Expr, ExprInner, Variable},
    gate::CurrOrNext,
};
use std::marker::PhantomData;

type Exp<F> = Expr<F, Column>;

pub struct PoseidonConstraintBuilder<F: Field, const S: usize, const R: usize, P: Params<F, S, R>> {
    constraints: Vec<Exp<F>>,
    _p: PhantomData<P>,
    mds: [[Exp<F>; S]; S],
    round_constants: [[Exp<F>; S]; R],
}

impl<F: Field + Default, const S: usize, const R: usize, P: Params<F, S, R> + Default> Default
    for PoseidonConstraintBuilder<F, S, R, P>
{
    fn default() -> Self {
        let mds = P::mds().map(|r| r.map(Exp::constant));
        let round_constants = P::constants().map(|r| r.map(Exp::constant));
        let constraints = Vec::new();
        Self {
            constraints,
            _p: PhantomData,
            mds,
            round_constants,
        }
    }
}

impl<F: Field, const S: usize, const R: usize, P: Params<F, S, R>> PoseidonInterpreter<F, S, R>
    for PoseidonConstraintBuilder<F, S, R, P>
{
    type Variable = Exp<F>;

    fn constrain(&mut self, cst: Self::Variable) {
        self.constraints.push(cst);
    }

    fn write(&mut self, x: &Self::Variable, to: Column) -> Self::Variable {
        let y = self.read_column(to);
        self.constraints.push(y.clone() - x.clone());
        y
    }

    fn read_column(&self, col: Column) -> Self::Variable {
        Exp::Atom(ExprInner::Cell(Variable {
            col,
            row: CurrOrNext::Curr,
        }))
    }

    fn constant(value: F) -> Self::Variable {
        Exp::Atom(ExprInner::Constant(value))
    }

    fn mds(&self) -> &[[Self::Variable; S]; S] {
        &self.mds
    }

    fn round_constants(&self) -> &[[Self::Variable; S]; R] {
        &self.round_constants
    }

    fn sbox(&self, v: Self::Variable) -> Self::Variable {
        Exp::Pow(Box::new(v), 7)
    }
}
