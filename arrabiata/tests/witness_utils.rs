//! Tests for utility functions in the witness environment.
//! Utilities are defined as functions indirectly used by the user.
//! A user is expected to use the gadget methods.
//! The API of the utilities is more subject to changes.

use arrabiata::{interpreter::InterpreterEnv, witness::Env, POSEIDON_STATE_SIZE};
use mina_curves::pasta::{Fp, Fq, Pallas, Vesta};
use num_bigint::BigInt;
use o1_utils::FieldHelpers;

#[test]
fn test_read_bit_of_folding_combiner() {
    let srs_log2_size = 6;
    let mut env = {
        let combiner = BigInt::from(42u64);
        let z0 = BigInt::from(1u64);
        let sponge_e1: [BigInt; POSEIDON_STATE_SIZE] = std::array::from_fn(|_i| BigInt::from(0u64));
        let mut env = Env::<Fp, Fq, Vesta, Pallas>::new(
            srs_log2_size,
            z0,
            sponge_e1.clone(),
            sponge_e1.clone(),
        );
        env.r = combiner;
        env
    };

    let zero_bi = BigInt::from(0u64);
    let one_bi = BigInt::from(1u64);

    // Checking the first bits, verifying it is in little endian
    let pos = env.allocate();
    let res = unsafe { env.read_bit_of_folding_combiner(pos, 0) };
    assert_eq!(res, zero_bi);
    let res = unsafe { env.read_bit_of_folding_combiner(pos, 1) };
    assert_eq!(res, one_bi);
    let res = unsafe { env.read_bit_of_folding_combiner(pos, 2) };
    assert_eq!(res, zero_bi);
    let res = unsafe { env.read_bit_of_folding_combiner(pos, 3) };
    assert_eq!(res, one_bi);
    let res = unsafe { env.read_bit_of_folding_combiner(pos, 4) };
    assert_eq!(res, zero_bi);
    let res = unsafe { env.read_bit_of_folding_combiner(pos, 5) };
    assert_eq!(res, one_bi);
    let res = unsafe { env.read_bit_of_folding_combiner(pos, 6) };
    assert_eq!(res, zero_bi);
    let res = unsafe { env.read_bit_of_folding_combiner(pos, 7) };
    assert_eq!(res, zero_bi);
    let res = unsafe { env.read_bit_of_folding_combiner(pos, 8) };
    assert_eq!(res, zero_bi);
}

#[test]
#[should_panic]
fn test_constrain_boolean_witness_negative_value() {
    let srs_log2_size = 2;
    let mut env = {
        let z0 = BigInt::from(1u64);
        let sponge_e1: [BigInt; POSEIDON_STATE_SIZE] = std::array::from_fn(|_i| BigInt::from(0u64));
        Env::<Fp, Fq, Vesta, Pallas>::new(srs_log2_size, z0, sponge_e1.clone(), sponge_e1.clone())
    };

    env.constrain_boolean(BigInt::from(-42));
}

#[test]
fn test_constrain_boolean_witness_positive_and_negative_modulus() {
    let srs_log2_size = 2;
    let mut env = {
        let z0 = BigInt::from(1u64);
        let sponge_e1: [BigInt; POSEIDON_STATE_SIZE] = std::array::from_fn(|_i| BigInt::from(0u64));
        Env::<Fp, Fq, Vesta, Pallas>::new(srs_log2_size, z0, sponge_e1.clone(), sponge_e1.clone())
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
    let sponge_e1: [BigInt; POSEIDON_STATE_SIZE] = std::array::from_fn(|_i| BigInt::from(42u64));
    let mut env = Env::<Fp, Fq, Vesta, Pallas>::new(
        srs_log2_size,
        BigInt::from(1u64),
        sponge_e1.clone(),
        sponge_e1.clone(),
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
    let sponge_e1: [BigInt; POSEIDON_STATE_SIZE] = std::array::from_fn(|_i| BigInt::from(42u64));
    let mut env = Env::<Fp, Fq, Vesta, Pallas>::new(
        srs_log2_size,
        BigInt::from(1u64),
        sponge_e1.clone(),
        sponge_e1.clone(),
    );
    let modulus: BigInt = Fp::modulus_biguint().into();
    let pos_x = env.allocate_public_input();
    let res = env.write_public_input(pos_x, modulus.clone() + BigInt::from(1u64));
    assert_eq!(res, BigInt::from(1u64));
    assert_eq!(env.public_state[0], BigInt::from(1u64));
}
