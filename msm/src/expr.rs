// @volhovm Not sure a whole file is necessary for just one type
// alias, but maybe more code will come.
// Consider moving to lib.rs

use ark_ff::Field;
use kimchi::circuits::{
    expr::{ConstantExpr, Expr, ExprInner, Variable},
    gate::CurrOrNext,
};

use crate::columns::Column;

/// An expression over /generic/ (not circuit-specific) columns
/// defined in the msm project. To represent constraints as multi
/// variate polynomials. The variables are over the columns.
///
/// For instance, if there are 3 columns X1, X2, X3, then to constraint X3 to be
/// equals to sum of the X1 and X2 on a row, we would use the multivariate
/// polynomial `X3 - X1 - X2 = 0`.
/// Using the expression framework, this constraint would be
/// ```
/// use kimchi::circuits::expr::{ConstantExprInner, ExprInner, Operations, Variable};
/// use kimchi::circuits::gate::CurrOrNext;
/// use kimchi_msm::columns::Column;
/// use kimchi_msm::expr::E;
/// pub type Fp = ark_bn254::Fr;
/// let x1 = E::<Fp>::Atom(
///     ExprInner::<Operations<ConstantExprInner<Fp>>, Column>::Cell(Variable {
///         col: Column::X(1),
///         row: CurrOrNext::Curr,
///     }),
/// );
/// let x2 = E::<Fp>::Atom(
///     ExprInner::<Operations<ConstantExprInner<Fp>>, Column>::Cell(Variable {
///         col: Column::X(1),
///         row: CurrOrNext::Curr,
///     }),
/// );
/// let x3 = E::<Fp>::Atom(
///     ExprInner::<Operations<ConstantExprInner<Fp>>, Column>::Cell(Variable {
///         col: Column::X(1),
///         row: CurrOrNext::Curr,
///     }),
/// );
/// let constraint = x3 - x1 - x2;
/// ```
/// A list of such constraints is used to represent the entire circuit and will
/// be used to build the quotient polynomial.
pub type E<F> = Expr<ConstantExpr<F>, Column>;

pub fn curr_cell<F: Field>(col: Column) -> E<F> {
    E::Atom(ExprInner::Cell(Variable {
        col,
        row: CurrOrNext::Curr,
    }))
}

pub fn next_cell<F: Field>(col: Column) -> E<F> {
    E::Atom(ExprInner::Cell(Variable {
        col,
        row: CurrOrNext::Next,
    }))
}

#[test]
fn test_debug_can_be_called_on_expr() {
    use crate::{columns::Column::*, Fp};
    println!("{:}", curr_cell::<Fp>(X(0)) + curr_cell(X(1)))
}
