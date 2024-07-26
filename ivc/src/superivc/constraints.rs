use ark_ff::Field;

use kimchi::circuits::expr::{ConstantExpr, Expr};

use super::{columns::SuperIVCColumn, interpreter::InterpreterEnv};

pub struct Env<Fp: Field> {
    pub current_idx: usize,
    pub constraints: Vec<Expr<ConstantExpr<Fp>, SuperIVCColumn>>,
}

impl<Fp: Field> InterpreterEnv for Env<Fp> {
    type Position = SuperIVCColumn;

    type Variable = Expr<ConstantExpr<Fp>, SuperIVCColumn>;
}
