// @volhovm Not sure a whole file is necessary for just one type
// alias, but maybe more code will come.
// Consider moving to lib.rs

use ark_ff::Field;
use kimchi::circuits::{
    berkeley_columns::BerkeleyChallengeTerm,
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
/// use kimchi::circuits::berkeley_columns::BerkeleyChallengeTerm;
/// use kimchi_msm::columns::{Column as GenericColumn};
/// use kimchi_msm::expr::E;
/// pub type Fp = ark_bn254::Fr;
/// pub type Column = GenericColumn<usize>;
/// let x1 = E::<Fp>::Atom(
///     ExprInner::<Operations<ConstantExprInner<Fp, BerkeleyChallengeTerm>>, Column>::Cell(Variable {
///         col: Column::Relation(1),
///         row: CurrOrNext::Curr,
///     }),
/// );
/// let x2 = E::<Fp>::Atom(
///     ExprInner::<Operations<ConstantExprInner<Fp, BerkeleyChallengeTerm>>, Column>::Cell(Variable {
///         col: Column::Relation(1),
///         row: CurrOrNext::Curr,
///     }),
/// );
/// let x3 = E::<Fp>::Atom(
///     ExprInner::<Operations<ConstantExprInner<Fp, BerkeleyChallengeTerm>>, Column>::Cell(Variable {
///         col: Column::Relation(1),
///         row: CurrOrNext::Curr,
///     }),
/// );
/// let constraint = x3 - x1 - x2;
/// ```
/// A list of such constraints is used to represent the entire circuit and will
/// be used to build the quotient polynomial.
pub type E<F> = Expr<ConstantExpr<F, BerkeleyChallengeTerm>, Column<usize>>;

pub fn curr_cell<F: Field>(col: Column<usize>) -> E<F> {
    E::Atom(ExprInner::Cell(Variable {
        col,
        row: CurrOrNext::Curr,
    }))
}

pub fn next_cell<F: Field>(col: Column<usize>) -> E<F> {
    E::Atom(ExprInner::Cell(Variable {
        col,
        row: CurrOrNext::Next,
    }))
}

#[test]
fn test_debug_can_be_called_on_expr() {
    use crate::{columns::Column::*, Fp};
    println!("{:}", curr_cell::<Fp>(Relation(0)) + curr_cell(Relation(1)))
}
