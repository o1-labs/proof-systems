use crate::columns::ColumnIndexer;
use crate::LIMBS_NUM;
use crate::columns::Column;
use kimchi::circuits::expr::ConstantExpr;
use kimchi::circuits::expr::Expr;


#[derive(Clone, Copy, Debug, PartialEq)]
/// Column indexer for MSM columns
pub enum MSMColumnIndexer {
    A(usize),
    B(usize),
    C(usize),
}

impl ColumnIndexer for MSMColumnIndexer {
    fn ix_to_column(self) -> Column {
        let to_column_inner = |offset, i| {
            assert!(i < LIMBS_NUM);
            Column::X(LIMBS_NUM * offset + i)
        };
        match self {
            MSMColumnIndexer::A(i) => to_column_inner(0, i),
            MSMColumnIndexer::B(i) => to_column_inner(1, i),
            MSMColumnIndexer::C(i) => to_column_inner(2, i),
        }
    }
}

/// Used to represent constraints as multi variate polynomials. The variables
/// are over the columns.
/// For instance, if there are 3 columns X1, X2, X3, then to constraint X3 to be
/// equals to sum of the X1 and X2 on a row, we would use the multivariate
/// polynomial `X3 - X1 - X2 = 0`.
/// Using the expression framework, this constraint would be
/// ```
/// use kimchi::circuits::expr::{ConstantExprInner, ExprInner, Operations, Variable};
/// use kimchi::circuits::gate::CurrOrNext;
/// use kimchi_msm::columns::Column;
/// use kimchi_msm::constraint::MSMExpr;
/// pub type Fp = ark_bn254::Fr;
/// let x1 = MSMExpr::<Fp>::Atom(
///     ExprInner::<Operations<ConstantExprInner<Fp>>, Column>::Cell(Variable {
///         col: Column::X(1),
///         row: CurrOrNext::Curr,
///     }),
/// );
/// let x2 = MSMExpr::<Fp>::Atom(
///     ExprInner::<Operations<ConstantExprInner<Fp>>, Column>::Cell(Variable {
///         col: Column::X(1),
///         row: CurrOrNext::Curr,
///     }),
/// );
/// let x3 = MSMExpr::<Fp>::Atom(
///     ExprInner::<Operations<ConstantExprInner<Fp>>, Column>::Cell(Variable {
///         col: Column::X(1),
///         row: CurrOrNext::Curr,
///     }),
/// );
/// let constraint = x3 - x1 - x2;
/// ```
/// A list of such constraints is used to represent the entire circuit and will
/// be used to build the quotient polynomial.
pub type MSMExpr<F> = Expr<ConstantExpr<F>, Column>;
