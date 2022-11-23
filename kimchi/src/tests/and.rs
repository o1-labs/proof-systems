use crate::circuits::{
    constraints::ConstraintSystem,
    gate::CircuitGate,
    polynomial::COLUMNS,
    polynomials::{and, xor},
    wires::Wire,
};

use ark_ec::AffineCurve;
use mina_curves::pasta::{Fp, Pallas, Vesta};
use num_bigint::BigUint;
use o1_utils::{
    big_bit_ops::{big_and, big_random},
    big_xor, FieldHelpers,
};

use super::framework::TestFramework;

type PallasField = <Pallas as AffineCurve>::BaseField;

fn create_test_constraint_system(bytes: usize) -> ConstraintSystem<Fp> {
    let (mut next_row, mut gates) = CircuitGate::<Fp>::create_and(0, bytes);

    // Temporary workaround for lookup-table/domain-size issue
    for _ in 0..(1 << 13) {
        gates.push(CircuitGate::zero(Wire::for_row(next_row)));
        next_row += 1;
    }

    ConstraintSystem::create(gates).build().unwrap()
}

// Manually checks the AND of the witness
fn check_and(
    witness: &[Vec<PallasField>; COLUMNS],
    bytes: usize,
    input1: &BigUint,
    input2: &BigUint,
) {
    let and_row = xor::num_xors(bytes * 8) + 1;
    assert_eq!(witness[3][and_row], PallasField::from(input1 + input2));
    assert_eq!(
        witness[4][and_row],
        PallasField::from(big_xor(input1, input2))
    );
    assert_eq!(
        witness[5][and_row],
        PallasField::from(big_and(input1, input2, bytes))
    );
}

fn test_and(in1: &BigUint, in2: &BigUint, bytes: usize) -> [Vec<PallasField>; COLUMNS] {
    let cs = create_test_constraint_system(bytes);
    let witness = and::create_and_witness(in1, in2, bytes);
    for row in 0..xor::num_xors(bytes * 8) + 2 {
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

// Function to create a prover and verifier to test the AND circuit
fn prove_and_verify(bytes: usize) {
    // Create
    let (mut next_row, mut gates) = CircuitGate::<Fp>::create_and(0, bytes);

    // Temporary workaround for lookup-table/domain-size issue
    for _ in 0..(1 << 13) {
        gates.push(CircuitGate::zero(Wire::for_row(next_row)));
        next_row += 1;
    }

    // Create inputs
    let input1 = big_random(8 * bytes);
    let input2 = big_random(8 * bytes);

    // Create witness
    let witness = and::create_and_witness(&input1, &input2, bytes);

    TestFramework::default()
        .gates(gates)
        .witness(witness)
        .lookup_tables(vec![xor::lookup_table()])
        .setup()
        .prove_and_verify();
}

#[test]
// End-to-end test
fn test_prove_and_verify() {
    prove_and_verify(8);
}

#[test]
// Test a AND of 64bit whose output is all ones with alternating inputs
fn test_and64_alternating() {
    let input1 = BigUint::from(6510615555426900570u64);
    let input2 = BigUint::from(11936128518282651045u64);
    let witness = test_and(&input1, &input2, 8);
    check_and(&witness, 8, &input1, &input2);
}

#[test]
// Test a AND of 64bit whose inputs are zero. Checks it works fine with non-dense values.
fn test_and64_zeros() {
    let zero = BigUint::from(0u8);
    let witness = test_and(&zero, &zero, 8);
    check_and(&witness, 8, &zero, &zero);
}

#[test]
// Tests a AND of 8 bits for a random input
fn test_and8_random() {
    let bytes = 1;
    let input1 = big_random(bytes * 8);
    let input2 = big_random(bytes * 8);
    let witness = test_and(&input1, &input2, bytes as usize);
    check_and(&witness, bytes as usize, &input1, &input2);
}

#[test]
// Tests a XOR of 16 bits for a random input
fn test_and16_random() {
    let bytes = 2;
    let input1 = big_random(bytes * 8);
    let input2 = big_random(bytes * 8);
    let witness = test_and(&input1, &input2, bytes as usize);
    check_and(&witness, bytes as usize, &input1, &input2);
}

#[test]
// Tests a AND of 32 bits for a random input
fn test_and32_random() {
    let bytes = 4;
    let input1 = big_random(bytes * 8);
    let input2 = big_random(bytes * 8);
    let witness = test_and(&input1, &input2, bytes as usize);
    check_and(&witness, bytes as usize, &input1, &input2);
}

#[test]
// Tests a AND of 64 bits for a random input
fn test_and64_random() {
    let bytes = 8;
    let input1 = big_random(bytes * 8);
    let input2 = big_random(bytes * 8);
    let witness = test_and(&input1, &input2, bytes as usize);
    check_and(&witness, bytes as usize, &input1, &input2);
}

#[test]
// Test a random AND of 128 bits
fn test_and128_random() {
    let bytes = 16;
    let input1 = big_random(bytes * 8);
    let input2 = big_random(bytes * 8);
    let witness = test_and(&input1, &input2, bytes as usize);
    check_and(&witness, bytes as usize, &input1, &input2);
}

#[test]
// Test AND when the sum of the inputs overflows the field size
fn test_and_overflow() {
    let input = PallasField::modulus_biguint() - BigUint::from(1u8);
    let witness = test_and(&input, &input, 256 / 8);
    check_and(&witness, 256 / 8, &input, &input);
}
