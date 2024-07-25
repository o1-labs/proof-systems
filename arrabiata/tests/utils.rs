use arrabiata::{interpreter::InterpreterEnv, witness::Env, POSEIDON_STATE_SIZE};
use mina_curves::pasta::{Fp, Fq, Pallas, Vesta};
use num_bigint::BigInt;
use num_integer::Integer;
use o1_utils::FieldHelpers;

// Testing that modulo on negative numbers gives a positive value.
// It is extensively used in the witness generation, therefore checking this
// assumption is important.
#[test]
fn test_biguint_from_bigint() {
    let a = BigInt::from(-9);
    let modulus = BigInt::from(10);
    let a = a.mod_floor(&modulus);
    assert_eq!(a, BigInt::from(1));
}

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
