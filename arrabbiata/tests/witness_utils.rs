//! Tests for utility functions in the witness environment.
//! Utilities are defined as functions indirectly used by the user.
//! A user is expected to use the gadget methods.
//! The API of the utilities is more subject to changes.

use arrabbiata::{
    curve::PlonkSpongeConstants, interpreter::InterpreterEnv, setup::IndexedRelation, witness::Env,
};
use mina_curves::pasta::{Fp, Fq, Pallas, Vesta};
use mina_poseidon::constants::SpongeConstants;
use num_bigint::BigInt;
use o1_utils::FieldHelpers;

#[test]
#[should_panic]
fn test_constrain_boolean_witness_negative_value() {
    let srs_log2_size = 2;
    let indexed_relation = IndexedRelation::new(srs_log2_size);
    let mut env = {
        let z0 = BigInt::from(1u64);
        let sponge_e1: [BigInt; PlonkSpongeConstants::SPONGE_WIDTH] =
            std::array::from_fn(|_i| BigInt::from(0u64));
        Env::<Fp, Fq, Vesta, Pallas>::new(
            z0,
            sponge_e1.clone(),
            sponge_e1.clone(),
            indexed_relation,
        )
    };

    env.constrain_boolean(BigInt::from(-42));
}

#[test]
fn test_constrain_boolean_witness_positive_and_negative_modulus() {
    let srs_log2_size = 2;
    let indexed_relation = IndexedRelation::new(srs_log2_size);
    let mut env = {
        let z0 = BigInt::from(1u64);
        let sponge_e1: [BigInt; PlonkSpongeConstants::SPONGE_WIDTH] =
            std::array::from_fn(|_i| BigInt::from(0u64));
        Env::<Fp, Fq, Vesta, Pallas>::new(
            z0,
            sponge_e1.clone(),
            sponge_e1.clone(),
            indexed_relation,
        )
    };

    let modulus: BigInt = Fp::modulus_biguint().into();
    env.constrain_boolean(modulus.clone());
    env.constrain_boolean(modulus.clone() + BigInt::from(1u64));
    env.constrain_boolean(-modulus.clone());
    env.constrain_boolean(-modulus.clone() + BigInt::from(1u64));
}

#[test]
fn test_write_column_return_the_result_reduced_in_field() {
    let srs_log2_size = 6;
    let indexed_relation = IndexedRelation::new(srs_log2_size);
    let sponge_e1: [BigInt; PlonkSpongeConstants::SPONGE_WIDTH] =
        std::array::from_fn(|_i| BigInt::from(42u64));
    let mut env = Env::<Fp, Fq, Vesta, Pallas>::new(
        BigInt::from(1u64),
        sponge_e1.clone(),
        sponge_e1.clone(),
        indexed_relation,
    );
    let modulus: BigInt = Fp::modulus_biguint().into();
    let pos_x = env.allocate();
    let res = env.write_column(pos_x, modulus.clone() + BigInt::from(1u64));
    assert_eq!(res, BigInt::from(1u64));
    assert_eq!(env.state[0], BigInt::from(1u64));
}

#[test]
fn test_write_public_return_the_result_reduced_in_field() {
    let srs_log2_size = 6;
    let indexed_relation = IndexedRelation::new(srs_log2_size);
    let sponge_e1: [BigInt; PlonkSpongeConstants::SPONGE_WIDTH] =
        std::array::from_fn(|_i| BigInt::from(42u64));
    let mut env = Env::<Fp, Fq, Vesta, Pallas>::new(
        BigInt::from(1u64),
        sponge_e1.clone(),
        sponge_e1.clone(),
        indexed_relation,
    );
    let modulus: BigInt = Fp::modulus_biguint().into();
    let pos_x = env.allocate_public_input();
    let res = env.write_public_input(pos_x, modulus.clone() + BigInt::from(1u64));
    assert_eq!(res, BigInt::from(1u64));
    assert_eq!(env.public_state[0], BigInt::from(1u64));
}
