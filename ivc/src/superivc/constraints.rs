use ark_ff::Field;

use kimchi::circuits::expr::{ConstantExpr, Expr};

use super::columns::SuperIVCColumn;

pub struct Env<Fp: Field> {
    pub current_idx: usize,
    pub constraints: Vec<Expr<ConstantExpr<Fp>, SuperIVCColumn>>,
}
