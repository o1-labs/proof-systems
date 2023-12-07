use ark_ff::{Field, One, Zero};
use kimchi::circuits::{
    expr::{ConstantExpr, Expr},
    gate::CurrOrNext,
};

use super::column::Column;

type E<F> = Expr<ConstantExpr<F>, Column>;

pub fn boolean<F: Field>(x: E<F>) -> E<F> {
    x.clone() * (x - Expr::one())
}

pub fn combine<F: Field>(constraints: impl Iterator<Item = E<F>>) -> E<F> {
    constraints
        .reduce(|acc, x| Expr::constant(ConstantExpr::Alpha) * acc + x)
        .unwrap_or(E::zero())
}

pub fn curr_cell<F: Field>(col: Column) -> E<F> {
    Expr::cell(col, CurrOrNext::Curr)
}
