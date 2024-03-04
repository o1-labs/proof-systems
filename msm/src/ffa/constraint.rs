use crate::{
    columns::{Column, ColumnIndexer},
    expr::MSMExpr,
    ffa::columns::FFAColumnIndexer,
    {Fp, LIMBS_NUM},
};
use kimchi::circuits::{
    expr::{ConstantExprInner, ExprInner, Operations, Variable},
    gate::CurrOrNext,
};

/// Access exprs for addition
pub fn get_exprs_add() -> Vec<MSMExpr<Fp>> {
    let mut limb_exprs: Vec<_> = vec![];
    for i in 0..LIMBS_NUM {
        let limb_constraint = {
            let a_i = MSMExpr::Atom(
                ExprInner::<Operations<ConstantExprInner<Fp>>, Column>::Cell(Variable {
                    col: FFAColumnIndexer::A(i).ix_to_column(),
                    row: CurrOrNext::Curr,
                }),
            );
            let b_i = MSMExpr::Atom(ExprInner::Cell(Variable {
                col: FFAColumnIndexer::B(i).ix_to_column(),
                row: CurrOrNext::Curr,
            }));
            let c_i = MSMExpr::Atom(ExprInner::Cell(Variable {
                col: FFAColumnIndexer::C(i).ix_to_column(),
                row: CurrOrNext::Curr,
            }));
            a_i + b_i - c_i
        };
        limb_exprs.push(limb_constraint);
    }
    limb_exprs
}

/// Get expressions for multiplication
pub fn get_exprs_mul() -> Vec<MSMExpr<Fp>> {
    let mut limb_exprs: Vec<_> = vec![];
    for i in 0..LIMBS_NUM {
        let limb_constraint = {
            let a_i = MSMExpr::Atom(
                ExprInner::<Operations<ConstantExprInner<Fp>>, Column>::Cell(Variable {
                    col: FFAColumnIndexer::A(i).ix_to_column(),
                    row: CurrOrNext::Curr,
                }),
            );
            let b_i = MSMExpr::Atom(ExprInner::Cell(Variable {
                col: FFAColumnIndexer::B(i).ix_to_column(),
                row: CurrOrNext::Curr,
            }));
            let d_i = MSMExpr::Atom(ExprInner::Cell(Variable {
                col: FFAColumnIndexer::D(i).ix_to_column(),
                row: CurrOrNext::Curr,
            }));
            a_i * b_i - d_i
        };
        limb_exprs.push(limb_constraint);
    }
    limb_exprs
}
