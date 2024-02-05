use ark_ec::AffineCurve;
use ark_ff::{Field, UniformRand};
use kimchi::circuits::domains::EvaluationDomains;
use kimchi::circuits::expr::{ConstantExpr, Expr};
use kimchi::circuits::expr::{ExprInner, Variable};
use kimchi::circuits::gate::CurrOrNext;
use num_bigint::{BigUint, RandBigInt};
use rand::thread_rng;

use o1_utils::field_helpers::FieldHelpers;
use o1_utils::foreign_field::ForeignElement;

use crate::column::MSMColumn;
use crate::proof::{Witness, WitnessColumns};
use crate::{Ff1, Fp, MsmBN254G1Affine, DOMAIN_SIZE, NUM_LIMBS};

pub type MSMExpr<F> = Expr<ConstantExpr<F>, MSMColumn>;

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
// TODO use more foreign_field.rs with from/to bigint conversion
fn limb_decompose(input: &Ff1) -> [Fp; NUM_LIMBS] {
    let input_bi: BigUint = FieldHelpers::to_biguint(input);
    let ff_el: ForeignElement<Fp, NUM_LIMBS> = ForeignElement::from_biguint(input_bi);
    ff_el.limbs
}

pub fn make_mips_witness() -> Witness<MsmBN254G1Affine> {
    let mut rng = thread_rng();

    let row_num = 1;
    assert!(row_num < DOMAIN_SIZE);

    let mut witness_columns_vec: Vec<WitnessColumns<Fp>> = vec![];

    for _row_i in 0..row_num {
        let a: Ff1 = Ff1::rand(&mut rng);
        let b: Ff1 = Ff1::rand(&mut rng);

        let a_limbs: [Fp; NUM_LIMBS] = limb_decompose(&a);
        let b_limbs: [Fp; NUM_LIMBS] = limb_decompose(&b);
        let c_limbs_vec: Vec<Fp> = a_limbs
            .iter()
            .zip(b_limbs.iter())
            .map(|(ai, bi)| *ai + *bi)
            .collect();
        let c_limbs: [Fp; NUM_LIMBS] = c_limbs_vec
            .try_into()
            .unwrap_or_else(|_| panic!("Length mismatch"));

        witness_columns_vec.push(WitnessColumns {
            a: a_limbs,
            b: b_limbs,
            c: c_limbs,
        });
    }

    Witness::from_witness_columns_vec(witness_columns_vec)
}
