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
use o1_utils::{big_and, big_xor, FieldFromBig, FieldHelpers};
use rand::{rngs::StdRng, SeedableRng};

use super::{framework::TestFramework, xor::initialize};

type PallasField = <Pallas as AffineCurve>::BaseField;

const RNG_SEED: [u8; 32] = [
    211, 31, 143, 75, 29, 255, 0, 126, 237, 193, 86, 160, 1, 90, 131, 221, 186, 168, 4, 95, 50, 48,
    89, 29, 13, 250, 215, 172, 130, 24, 164, 162,
];

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
    input1: PallasField,
    input2: PallasField,
) {
    let and_row = xor::num_xors(bytes * 8) + 1;
    let big_in1 = input1.to_biguint();
    let big_in2 = input2.to_biguint();
    assert_eq!(witness[3][and_row], PallasField::from(input1 + input2));
    assert_eq!(
        witness[4][and_row],
        PallasField::from(big_xor(&big_in1, &big_in2))
    );
    assert_eq!(
        witness[5][and_row],
        PallasField::from(big_and(&big_in1, &big_in2, bytes))
    );
}

fn test_and(
    in1: Option<PallasField>,
    in2: Option<PallasField>,
    bytes: usize,
) -> [Vec<PallasField>; COLUMNS] {
    let rng = &mut StdRng::from_seed(RNG_SEED);

    let cs = create_test_constraint_system(bytes);

    let in1 = initialize(in1, Some(bytes * 8), rng);
    let in2 = initialize(in2, Some(bytes * 8), rng);

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

    check_and(&witness, bytes, in1, in2);

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
    let input1 = PallasField::random(8 * bytes);
    let input2 = PallasField::random(8 * bytes);

    // Create witness
    let witness = and::create_and_witness(input1, input2, bytes);

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
    let input1 = PallasField::from(6510615555426900570u64);
    let input2 = PallasField::from(11936128518282651045u64);
    test_and(Some(input1), Some(input2), 8);
}

#[test]
// Test a AND of 64bit whose inputs are zero. Checks it works fine with non-dense values.
fn test_and64_zeros() {
    let zero = PallasField::from(0u8);
    test_and(Some(zero), Some(zero), 8);
}

#[test]
// Tests a AND of 8 bits for a random input
fn test_and8_random() {
    test_and(None, None, 1);
}

#[test]
// Tests a XOR of 16 bits for a random input
fn test_and16_random() {
    test_and(None, None, 2);
}

#[test]
// Tests a AND of 32 bits for a random input
fn test_and32_random() {
    test_and(None, None, 4);
}

#[test]
// Tests a AND of 64 bits for a random input
fn test_and64_random() {
    test_and(None, None, 8);
}

#[test]
// Test a random AND of 128 bits
fn test_and128_random() {
    test_and(None, None, 16);
}

#[test]
// Test AND when the sum of the inputs overflows the field size
fn test_and_overflow() {
    let input =
        PallasField::from_biguint(&(PallasField::modulus_biguint() - BigUint::from(1u8))).unwrap();
    test_and(Some(input), Some(input), 256 / 8);
}

#[test]
// Test AND when the sum of the inputs overflows the field size
fn test_and_overflow_one() {
    let input =
        PallasField::from_biguint(&(PallasField::modulus_biguint() - BigUint::from(1u8))).unwrap();
    test_and(Some(input), Some(PallasField::from(1u8)), 256 / 8);
}
