use ark_ec::AffineCurve;
use ark_ff::{Field, UniformRand};
use kimchi::circuits::domains::EvaluationDomains;
use kimchi::circuits::expr::{ConstantExpr, Expr};
use kimchi::circuits::expr::{ExprInner, Variable};
use kimchi::circuits::gate::CurrOrNext;
use rand::thread_rng;

use crate::column::MSMColumn;
use crate::proof::{Witness, WitnessColumns};
use crate::{Ff1, Fp, MsmBN254G1Affine, DOMAIN_SIZE, NUM_LIMBS};

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
        let a_i = MSMExpr::Atom(ExprInner::<
            kimchi::circuits::expr::Operations<kimchi::circuits::expr::ConstantExprInner<Fp>>,
            MSMColumn,
        >::Cell(Variable {
            col: MSMColumn::A(i),
            row: CurrOrNext::Curr,
        }));
        let b_i = MSMExpr::Atom(ExprInner::Cell(Variable {
            col: MSMColumn::B(i),
            row: CurrOrNext::Curr,
        }));
        let c_i = MSMExpr::Atom(ExprInner::Cell(Variable {
            col: MSMColumn::C(i),
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

#[allow(dead_code)]
fn limb_decompose(_input: Ff1) -> Vec<u8> {
    // TODO see foreign_field.rs with from/to bigint conversion
    unimplemented!()
}

pub fn make_mips_witness() -> Witness<MsmBN254G1Affine> {
    let mut rng = thread_rng();

    let row_num = 100;
    assert!(row_num < DOMAIN_SIZE);

    let mut witness_columns_vec: Vec<WitnessColumns<Fp>> = vec![];

    for _row_i in 0..row_num {
        let a: Ff1 = Ff1::rand(&mut rng);
        let b: Ff1 = Ff1::rand(&mut rng);

        let a_limbs: Vec<u8> = limb_decompose(a);
        let b_limbs: Vec<u8> = limb_decompose(b);
        let c_limbs: Vec<u64> = a_limbs
            .iter()
            .zip(b_limbs.iter())
            .map(|(ai, bi)| (*ai as u64) + (*bi as u64))
            .collect();

        let mut witness_a: Vec<Fp> = vec![];
        let mut witness_b: Vec<Fp> = vec![];
        let mut witness_c: Vec<Fp> = vec![];

        for i in 0..NUM_LIMBS {
            witness_a.push(From::from(a_limbs[i] as u64));
            witness_b.push(From::from(b_limbs[i] as u64));
            witness_c.push(From::from(c_limbs[i]));
        }

        witness_columns_vec.push(WitnessColumns {
            a: witness_a
                .try_into()
                .unwrap_or_else(|_| panic!("Length mismatch")),
            b: witness_b
                .try_into()
                .unwrap_or_else(|_| panic!("Length mismatch")),
            c: witness_c
                .try_into()
                .unwrap_or_else(|_| panic!("Length mismatch")),
        });
    }

    Witness::from_witness_columns_vec(witness_columns_vec)
}
