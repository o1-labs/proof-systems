use crate::column::MSMColumn;
use ark_ff::Field;
use kimchi::circuits::expr::{ConstantExpr, Expr};

pub type E<F> = Expr<ConstantExpr<F>, MSMColumn>;

pub struct Env<F: Field> {
    // TODO
    pub(crate) _constraints: Vec<E<F>>,
}
