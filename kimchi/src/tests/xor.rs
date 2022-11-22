use std::cmp::max;

use crate::circuits::{
    constraints::ConstraintSystem,
    gate::CircuitGate,
    polynomial::COLUMNS,
    polynomials::xor::{self},
    wires::Wire,
};

use ark_ec::AffineCurve;
use ark_ff::{Field, One};
use mina_curves::pasta::{Fp, Pallas, Vesta};
use num_bigint::BigUint;
use o1_utils::{big_bit_ops::*, FieldFromBig, FieldHelpers};

use super::framework::TestFramework;

type PallasField = <Pallas as AffineCurve>::BaseField;

const XOR: bool = true;

fn create_test_constraint_system_xor(bits: u32) -> ConstraintSystem<Fp> {
    let (mut next_row, mut gates) = CircuitGate::<Fp>::create_xor_gadget(0, bits);

    // Temporary workaround for lookup-table/domain-size issue
    for _ in 0..(1 << 13) {
        gates.push(CircuitGate::zero(Wire::for_row(next_row)));
        next_row += 1;
    }

    ConstraintSystem::create(gates).build().unwrap()
}

// General test for Xor
fn test_xor(in1: PallasField, in2: PallasField, bits: Option<u32>) -> [Vec<PallasField>; COLUMNS] {
    // If user specified a concrete number of bits, use that (if they are sufficient to hold both inputs)
    // Otherwise, use the max number of bits required to hold both inputs (if only one, the other is zero)
    let bits1 = big_bits(&in1.to_biguint()) as u32;
    let bits2 = big_bits(&in2.to_biguint()) as u32;
    let bits = bits.map_or(0, |b| b); // 0 or bits
    let bits = max(bits, max(bits1, bits2));

    let cs = create_test_constraint_system_xor(bits);
    let witness = xor::create_xor_witness(in1, in2, bits);
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

// Returns a given crumb of 4 bits
pub(crate) fn xor_crumb(word: BigUint, crumb: usize) -> BigUint {
    (word >> (4 * crumb)) % 2u128.pow(4)
}

// Returns the all ones BigUint of bits length
pub(crate) fn all_ones(bits: u32) -> PallasField {
    PallasField::from(2u128).pow(&[bits as u64]) - PallasField::one()
}

// Manually checks the XOR of each crumb in the witness
pub(crate) fn check_xor(
    witness: &[Vec<PallasField>; COLUMNS],
    bits: u32,
    input1: PallasField,
    input2: PallasField,
    not: bool,
) {
    let input1 = input1.to_biguint();
    let input2 = input2.to_biguint();
    let ini_row = if not == XOR { 0 } else { 1 };
    for x in 0..xor::num_xors(bits) {
        let in1 = (0..4)
            .map(|i| xor_crumb(input1.clone(), i + 4 * x))
            .collect::<Vec<BigUint>>();
        let in2 = (0..4)
            .map(|i| xor_crumb(input2.clone(), i + 4 * x))
            .collect::<Vec<BigUint>>();
        for crumb in 0..4 {
            assert_eq!(
                witness[11 + crumb][x + ini_row],
                PallasField::from(big_xor(&in1[crumb], &in2[crumb]))
            );
        }
    }
    assert_eq!(
        witness[2][ini_row],
        PallasField::from(big_xor(&input1, &input2))
    );
}

#[test]
// End-to-end test of XOR
fn test_prove_and_verify_xor() {
    let bits = 64;
    // Create
    let (mut next_row, mut gates) = CircuitGate::<Fp>::create_xor_gadget(0, bits);

    // Temporary workaround for lookup-table/domain-size issue
    for _ in 0..(1 << 13) {
        gates.push(CircuitGate::zero(Wire::for_row(next_row)));
        next_row += 1;
    }

    // Create witness and random inputs
    let witness = xor::create_xor_witness(
        PallasField::from_biguint(&big_random(bits)).unwrap(),
        PallasField::from_biguint(&big_random(bits)).unwrap(),
        bits,
    );

    TestFramework::default()
        .gates(gates)
        .witness(witness)
        .lookup_tables(vec![xor::lookup_table()])
        .setup()
        .prove_and_verify();
}

#[test]
// Test a XOR of 64bit whose output is all ones with alternating inputs
fn test_xor64_alternating() {
    let input1 = PallasField::from(6510615555426900570u64);
    let input2 = PallasField::from(11936128518282651045u64);
    let witness = test_xor(input1, input2, Some(64));
    assert_eq!(witness[2][0], PallasField::from(2u128.pow(64) - 1));
    assert_eq!(witness[2][1], PallasField::from(2u64.pow(48) - 1));
    assert_eq!(witness[2][2], PallasField::from(2u64.pow(32) - 1));
    assert_eq!(witness[2][3], PallasField::from(2u32.pow(16) - 1));
    assert_eq!(witness[2][4], PallasField::from(0));
    check_xor(&witness, 64, input1, input2, XOR);
}

#[test]
// Test a XOR of 64bit whose inputs are zero. Checks it works fine with non-dense values.
fn test_xor64_zeros() {
    // forces zero to fit in 64 bits even if it only needs 1 bit
    let zero = PallasField::from_biguint(&BigUint::from(0u32)).unwrap();
    let witness = test_xor(zero, zero, Some(64));
    assert_eq!(witness[2][0], PallasField::from(0));
    check_xor(&witness, 64, zero, zero, XOR);
}

#[test]
// Test a XOR of 64bit whose inputs are all zero and all one. Checks it works fine with non-dense values.
fn test_xor64_zero_one() {
    let zero = PallasField::from_biguint(&BigUint::from(0u32)).unwrap();
    let all_ones = all_ones(64);
    let witness = test_xor(zero, all_ones, None);
    assert_eq!(witness[2][0], all_ones);
    check_xor(&witness, 64, zero, all_ones, XOR);
}

#[test]
// Tests a XOR of 8 bits for a random input
fn test_xor8_random() {
    let input1 = PallasField::random(8);
    let input2 = PallasField::random(8);
    let witness = test_xor(input1, input2, Some(8));
    check_xor(&witness, 8, input1, input2, XOR);
}

#[test]
// Tests a XOR of 16 bits for a random input
fn test_xor16_random() {
    let input1 = PallasField::random(16);
    let input2 = PallasField::random(16);
    let witness = test_xor(input1, input2, Some(16));
    check_xor(&witness, 16, input1, input2, XOR);
}

#[test]
// Tests a XOR of 32 bits for a random input
fn test_xor32_random() {
    let input1 = PallasField::random(32);
    let input2 = PallasField::random(32);
    let witness = test_xor(input1, input2, Some(32));
    check_xor(&witness, 32, input1, input2, XOR);
}

#[test]
// Tests a XOR of 64 bits for a random input
fn test_xor64_random() {
    let input1 = PallasField::random(64);
    let input2 = PallasField::random(64);
    let witness = test_xor(input1, input2, Some(64));
    check_xor(&witness, 64, input1, input2, XOR);
}

#[test]
// Test a random XOR of 128 bits
fn test_xor128_random() {
    let input1 = PallasField::random(128);
    let input2 = PallasField::random(128);
    let witness = test_xor(input1, input2, Some(128));
    check_xor(&witness, 128, input1, input2, XOR);
}
