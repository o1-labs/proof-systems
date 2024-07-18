use kimchi::circuits::expr::{ConstantExpr, Expr};

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Column {
    X(usize),
}

pub type E<Fp> = Expr<ConstantExpr<Fp>, Column>;
