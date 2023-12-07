use kimchi::circuits::expr::{ConstantExpr, Expr};

use super::column::Column;

type _E<F> = Expr<ConstantExpr<F>, Column>;
