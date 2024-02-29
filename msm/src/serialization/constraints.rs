use kimchi::circuits::expr::{ConstantExpr, Expr};

use crate::columns::Column;

pub struct Env<Fp> {
    pub constraints: Vec<Expr<ConstantExpr<Fp>, Column>>,
}
