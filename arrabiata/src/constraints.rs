use ark_ff::Field;

use kimchi::circuits::expr::{ConstantExpr, Expr};

use super::{columns::Column, interpreter::InterpreterEnv};

pub struct Env<Fp: Field> {
    pub constraints: Vec<Expr<ConstantExpr<Fp>, Column>>,
}

impl<Fp: Field> InterpreterEnv for Env<Fp> {
    type Position = Column;

    type Variable = Expr<ConstantExpr<Fp>, Column>;
}
