use ark_ff::Field;

use kimchi::circuits::expr::{ConstantExpr, Expr, ExprInner, Variable};
use kimchi::circuits::gate::CurrOrNext;

use crate::columns::Column;
use crate::columns::{ColumnIndexer, MSMColumnIndexer};
use crate::{Fp, LIMBS_NUM};

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

#[allow(dead_code)]
pub struct BuilderEnv<F: Field> {
    // TODO something like a running list of constraints
    pub(crate) constraints: Vec<MSMExpr<F>>,
    // TODO An accumulated elliptic curve sum for the sub-MSM algorithm
    pub(crate) accumulated_result: F,
}

pub fn make_msm_constraint() -> MSMExpr<Fp> {
    let mut limb_constraints: Vec<_> = vec![];

    for i in 0..LIMBS_NUM {
        let a_i = MSMExpr::Atom(ExprInner::<
            kimchi::circuits::expr::Operations<kimchi::circuits::expr::ConstantExprInner<Fp>>,
            Column,
        >::Cell(Variable {
            col: MSMColumnIndexer::A(i).ix_to_column(),
            row: CurrOrNext::Curr,
        }));
        let b_i = MSMExpr::Atom(ExprInner::Cell(Variable {
            col: MSMColumnIndexer::B(i).ix_to_column(),
            row: CurrOrNext::Curr,
        }));
        let c_i = MSMExpr::Atom(ExprInner::Cell(Variable {
            col: MSMColumnIndexer::C(i).ix_to_column(),
            row: CurrOrNext::Curr,
        }));
        let limb_constraint = a_i + b_i - c_i;
        limb_constraints.push(limb_constraint);
    }

    let combined_constraint =
        Expr::combine_constraints(0..(limb_constraints.len() as u32), limb_constraints);

    println!("{:?}", combined_constraint);
    combined_constraint
}
