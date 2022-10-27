use crate::circuits::{
    constraints::ConstraintSystem, gate::CircuitGate, polynomial::COLUMNS, polynomials::xor,
    wires::Wire,
};

use ark_ec::AffineCurve;
use mina_curves::pasta::{Fp, Pallas, Vesta};
use rand::Rng;

type PallasField = <Pallas as AffineCurve>::BaseField;

fn create_test_constraint_system(bits: usize) -> ConstraintSystem<Fp> {
    let (mut next_row, mut gates) = CircuitGate::<Fp>::create_xor(0, bits);

    // Temporary workaround for lookup-table/domain-size issue
    for _ in 0..(1 << 13) {
        gates.push(CircuitGate::zero(Wire::new(next_row)));
        next_row += 1;
    }

    ConstraintSystem::create(gates).build().unwrap()
}

fn test_xor(in1: u128, in2: u128, bits: usize) -> [Vec<PallasField>; COLUMNS] {
    let cs = create_test_constraint_system(bits);
    let witness = xor::create(in1, in2, bits);
    for row in 0..xor::num_xors(bits) + 1 {
        assert_eq!(
            cs.gates[row].verify_witness::<Vesta>(
                row,
                &witness,
                &cs,
                &witness[0][0..cs.public].to_vec()
            ),
            Ok(())
        );
    }
    witness
}

#[test]
// Test a XOR of 64bit whose output is all ones with alternating inputs
fn test_xor64_alternating() {
    let witness = test_xor(6510615555426900570, 11936128518282651045, 64);
    assert_eq!(witness[2][0], PallasField::from(2u128.pow(64) - 1));
    assert_eq!(witness[2][1], PallasField::from(2u64.pow(48) - 1));
    assert_eq!(witness[2][2], PallasField::from(2u64.pow(32) - 1));
    assert_eq!(witness[2][3], PallasField::from(2u32.pow(16) - 1));
    assert_eq!(witness[2][4], PallasField::from(0));
}

#[test]
// Test a XOR of 64bit whose inputs are zero. Checks it works fine with non-dense values.
fn test_xor64_zeros() {
    let witness = test_xor(0, 0, 64);
    assert_eq!(witness[2][0], PallasField::from(0));
}

#[test]
// Test a XOR of 64bit whose inputs are all zero and all one. Checks it works fine with non-dense values.
fn test_xor64_zero_one() {
    let all_ones = 2u128.pow(64) - 1;
    let witness = test_xor(0, all_ones, 64);
    assert_eq!(witness[2][0], PallasField::from(all_ones));
}

#[test]
// Tests a XOR of 8 bits for a random input
fn test_xor8_random() {
    let input1 = rand::thread_rng().gen_range(0..255);
    let input2 = rand::thread_rng().gen_range(0..255);
    let output = input1 ^ input2;
    let witness = test_xor(input1 as u128, input2 as u128, 16);
    assert_eq!(witness[2][0], PallasField::from(output));
}

#[test]
// Tests a XOR of 16 bits for a random input
fn test_xor16_random() {
    let input1 = rand::thread_rng().gen_range(0..2u32.pow(16) - 1);
    let input2 = rand::thread_rng().gen_range(0..2u32.pow(16) - 1);
    let output = input1 ^ input2;
    let witness = test_xor(input1 as u128, input2 as u128, 16);
    assert_eq!(witness[2][0], PallasField::from(output));
}

#[test]
// Tests a XOR of 32 bits for a random input
fn test_xor32_random() {
    let input1 = rand::thread_rng().gen_range(0..2u64.pow(32) - 1);
    let input2 = rand::thread_rng().gen_range(0..2u64.pow(32) - 1);
    let output = input1 ^ input2;
    let witness = test_xor(input1 as u128, input2 as u128, 32);
    assert_eq!(witness[2][0], PallasField::from(output));
}

#[test]
// Tests a XOR of 64 bits for a random input
fn test_xor64_random() {
    let input1 = rand::thread_rng().gen_range(0..2u128.pow(64) - 1);
    let input2 = rand::thread_rng().gen_range(0..2u128.pow(64) - 1);
    let output = input1 ^ input2;
    let witness = test_xor(input1, input2, 64);
    assert_eq!(witness[2][0], PallasField::from(output));
}

#[test]
// Test a random XOR of 128 bits
fn test_xor128_random() {
    let input1 = rand::thread_rng().gen_range(0..2u128.pow(127));
    let input2 = rand::thread_rng().gen_range(0..2u128.pow(127));
    let output = input1 ^ input2;
    let witness = test_xor(input1, input2, 128);
    assert_eq!(witness[2][0], PallasField::from(output));
}
