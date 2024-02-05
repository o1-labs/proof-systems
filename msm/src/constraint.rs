use crate::column::MSMColumn;
use ark_ff::Field;
use kimchi::circuits::expr::{ConstantExpr, Expr};

pub type E<F> = Expr<ConstantExpr<F>, MSMColumn>;

// t(X) = CONSTRAINT_1 * 1 + \
//        CONSTRAINT_2 * \alpha + \
//        CONSTRAINT_3 * \alpha^2
//        ...
pub fn combine<F: Field>(constraints: Vec<E<F>>) -> E<F> {
    constraints
        .reduce(|acc, x| Expr::constant(ConstantExpr::Alpha) * acc + x)
        .unwrap_or(E::zero())
}

pub struct Env<F: Field> {
    // TODO
    pub(crate) _constraints: Vec<E<F>>,
}
