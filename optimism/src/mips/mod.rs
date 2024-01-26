use kimchi::circuits::expr::{ConstantExpr, Expr};

use self::column::Column as MIPSColumn;

pub mod column;
pub mod constraints;
pub mod interpreter;
pub mod proof;
pub mod registers;
pub mod witness;

pub(crate) type E<F> = Expr<ConstantExpr<F>, MIPSColumn>;
