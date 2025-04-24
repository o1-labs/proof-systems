//! Tests for utility functions in the witness environment.
//! Utilities are defined as functions indirectly used by the user.
//! A user is expected to use the gadget methods.
//! The API of the utilities is more subject to changes.

use arrabbiata::{
    interpreter::InterpreterEnv, setup::IndexedRelation, witness::Env, MIN_SRS_LOG2_SIZE,
};
use mina_curves::pasta::{Fp, Fq, Pallas, Vesta};
use num_bigint::BigInt;
use o1_utils::FieldHelpers;

#[test]
#[should_panic]
fn test_constrain_boolean_witness_negative_value() {
    let indexed_relation = IndexedRelation::new(MIN_SRS_LOG2_SIZE);
    let mut env = {
        let z0 = BigInt::from(1u64);
        Env::<Fp, Fq, Vesta, Pallas>::new(z0, indexed_relation)
    };

    env.constrain_boolean(BigInt::from(-42));
}

#[test]
fn test_constrain_boolean_witness_positive_and_negative_modulus() {
    let indexed_relation = IndexedRelation::new(MIN_SRS_LOG2_SIZE);
    let mut env = {
        let z0 = BigInt::from(1u64);
        Env::<Fp, Fq, Vesta, Pallas>::new(z0, indexed_relation)
    };

    let modulus: BigInt = Fp::modulus_biguint().into();
    env.constrain_boolean(modulus.clone());
    env.constrain_boolean(modulus.clone() + BigInt::from(1u64));
    env.constrain_boolean(-modulus.clone());
    env.constrain_boolean(-modulus.clone() + BigInt::from(1u64));
}

#[test]
fn test_write_column_return_the_result_reduced_in_field() {
    let indexed_relation = IndexedRelation::new(MIN_SRS_LOG2_SIZE);
    let mut env = Env::<Fp, Fq, Vesta, Pallas>::new(BigInt::from(1u64), indexed_relation);
    let modulus: BigInt = Fp::modulus_biguint().into();
    let pos_x = env.allocate();
    let res = env.write_column(pos_x, modulus.clone() + BigInt::from(1u64));
    assert_eq!(res, BigInt::from(1u64));
    assert_eq!(env.state[0], BigInt::from(1u64));
}
