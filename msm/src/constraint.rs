use ark_ff::Field;
use kimchi::circuits::expr::{ConstantExpr, Expr};
use kimchi::circuits::expr::{ExprInner, Variable};
use kimchi::circuits::gate::CurrOrNext;

use crate::column::MSMColumn;
use crate::{Fp, NUM_LIMBS};

pub type MSMExpr<F> = Expr<ConstantExpr<F>, MSMColumn>;

// t(X) = CONSTRAINT_1 * 1 + \
//        CONSTRAINT_2 * \alpha + \
//        CONSTRAINT_3 * \alpha^2
//        ...
//pub fn combine_within_constraint<F: Field>(constraints: Vec<E<F>>) -> E<F> {
//    let zero: E<F> = Expr::<ConstantExpr<F>, MSMColumn>::zero();
//    let alpha: E<F> = Expr::from(ChallengeTerm::Alpha);
//    constraints
//        .iter()
//        .reduce(|acc, x| alpha.clone() * *acc + x.clone())
//        .unwrap_or(&zero)
//        .clone()
//}

#[allow(dead_code)]
pub struct BuilderEnv<F: Field> {
    // TODO something like a running list of constraints
    pub(crate) constraints: Vec<MSMExpr<F>>,
    // TODO An accumulated elliptic curve sum for the sub-MSM algorithm
    pub(crate) accumulated_result: F,
}

// constraints mips_demo combine(constrainsts) with alpha

pub fn make_mips_constraint() -> MSMExpr<Fp> {
    let mut limb_constraints: Vec<_> = vec![];

    for i in 0..NUM_LIMBS {
        let a_1 = MSMExpr::Atom(ExprInner::<
            kimchi::circuits::expr::Operations<kimchi::circuits::expr::ConstantExprInner<Fp>>,
            MSMColumn,
        >::Cell(Variable {
            col: MSMColumn::A(i),
            row: CurrOrNext::Curr,
        }));
        let b_1 = MSMExpr::Atom(ExprInner::Cell(Variable {
            col: MSMColumn::B(i),
            row: CurrOrNext::Curr,
        }));
        let c_1 = MSMExpr::Atom(ExprInner::Cell(Variable {
            col: MSMColumn::C(i),
            row: CurrOrNext::Curr,
        }));
        let limb_constraint = a_1 + b_1 - c_1;
        limb_constraints.push(limb_constraint);
    }

    let combined_constraint =
        Expr::combine_constraints(0..(limb_constraints.len() as u32), limb_constraints);

    println!("{:?}", combined_constraint);
    combined_constraint
}
