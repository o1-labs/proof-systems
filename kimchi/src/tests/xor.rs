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
use o1_utils::{big_bits, big_not, big_xor, FieldHelpers};
use rand::Rng;

use super::framework::TestFramework;

type PallasField = <Pallas as AffineCurve>::BaseField;

const XOR: bool = true;
const NOT: bool = false;

fn create_test_constraint_system(bits: u32, xor: bool) -> ConstraintSystem<Fp> {
    let (mut next_row, mut gates) = if xor {
        CircuitGate::<Fp>::create_xor_gadget(0, bits)
    } else {
        CircuitGate::<Fp>::create_not_gadget(0, bits)
    };

    // Temporary workaround for lookup-table/domain-size issue
    for _ in 0..(1 << 13) {
        gates.push(CircuitGate::zero(Wire::new(next_row)));
        next_row += 1;
    }

    ConstraintSystem::create(gates).build().unwrap()
}

fn create_test_constraint_system_gnrc(double: bool) -> ConstraintSystem<Fp> {
    let (mut next_row, mut gates) = CircuitGate::<Fp>::create_not_gnrc(double);

    // Temporary workaround for lookup-table/domain-size issue
    for _ in 0..(1 << 13) {
        gates.push(CircuitGate::zero(Wire::new(next_row)));
        next_row += 1;
    }

    ConstraintSystem::create(gates).build().unwrap()
}

// Produces a random BigUint of a given number of bits
fn big_random(bits: u32) -> BigUint {
    if bits == 0 {
        panic!("Cannot generate a random number of 0 bits");
    }
    let bytes = bits / 8;
    let extra = bits % 8;
    let mut big = (0..bytes)
        .map(|_| rand::thread_rng().gen_range(0..255))
        .collect::<Vec<u8>>();
    if extra > 0 {
        big.push(rand::thread_rng().gen_range(0..2u8.pow(extra)));
    }
    BigUint::from_bytes_le(&big)
}

fn test_xor(in1: &BigUint, in2: &BigUint, bits: Option<u32>) -> [Vec<PallasField>; COLUMNS] {
    // If user specified a concrete number of bits, use that (if they are sufficient to hold both inputs)
    // Otherwise, use the max number of bits required to hold both inputs (if only one, the other is zero)
    let bits1 = big_bits(&in1) as u32;
    let bits2 = big_bits(&in2) as u32;
    let bits = bits.map_or(0, |b| b); // 0 or bits
    let bits = max(bits, max(bits1, bits2));

    let cs = create_test_constraint_system(bits, XOR);
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

// Tester for not gate
fn test_not(inp: &BigUint, bits: Option<u32>) -> [Vec<PallasField>; COLUMNS] {
    // If user specified a concrete number of bits, use that (if they are sufficient to hold the input)
    // Otherwise, use the length of the input
    let bits = max(big_bits(&inp) as u32, bits.unwrap_or(0));

    let cs = create_test_constraint_system(bits, NOT);
    let witness = xor::create_not_witness(inp, Some(bits));
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

// Tester for not gate generic
fn test_not_gnrc(inp1: &BigUint, inp2: &Option<BigUint>, bits: u32) -> [Vec<PallasField>; COLUMNS] {
    let cs = create_test_constraint_system_gnrc(inp2.is_some());
    let witness = xor::create_not_gnrc_witness(inp1, inp2, bits);
    // test public input and not generic gate
    for row in 0..2 {
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
fn xor_crumb(word: &BigUint, crumb: usize) -> BigUint {
    (word >> (4 * crumb)) % 2u128.pow(4)
}

// Returns the all ones BigUint of bits length
fn all_ones(bits: u32) -> BigUint {
    BigUint::from_bytes_le(
        &(PallasField::from(2u128).pow(&[bits as u64]) - PallasField::one()).to_bytes(),
    )
}

// Manually checks the XOR of each crumb in the witness
fn check_xor(witness: &[Vec<PallasField>; COLUMNS], bits: u32, input1: &BigUint, input2: &BigUint) {
    for x in 0..xor::num_xors(bits) {
        let in1 = (0..4)
            .map(|i| xor_crumb(input1, i + 4 * x))
            .collect::<Vec<BigUint>>();
        let in2 = (0..4)
            .map(|i| xor_crumb(input2, i + 4 * x))
            .collect::<Vec<BigUint>>();
        for crumb in 0..4 {
            assert_eq!(
                witness[11 + crumb][x],
                PallasField::from(big_xor(&in1[crumb], &in2[crumb]))
            );
        }
    }
    assert_eq!(witness[2][0], PallasField::from(big_xor(&input1, &input2)));
}

// Manually checks the NOT of each crumb in the witness
fn check_not(witness: &[Vec<PallasField>; COLUMNS], input: &BigUint, bits: Option<u32>) {
    let bits = max(big_bits(&input) as u32, bits.unwrap_or(0));
    check_xor(&witness, bits, &input, &all_ones(bits));
    assert_eq!(witness[2][0], PallasField::from(big_not(input, Some(bits))));
}

// Function to create a prover and verifier to test the XOR circuit
fn prove_and_verify(bits: u32, xor: bool) {
    // Create
    let (mut next_row, mut gates) = if xor {
        CircuitGate::<Fp>::create_xor_gadget(0, bits)
    } else {
        CircuitGate::<Fp>::create_not_gadget(0, bits)
    };

    // Temporary workaround for lookup-table/domain-size issue
    for _ in 0..(1 << 13) {
        gates.push(CircuitGate::zero(Wire::new(next_row)));
        next_row += 1;
    }

    // Create witness and random inputs
    let witness = if xor {
        xor::create_xor_witness(&big_random(bits), &big_random(bits), bits)
    } else {
        xor::create_not_witness(&big_random(bits), Some(bits))
    };

    TestFramework::default()
        .gates(gates)
        .witness(witness)
        .lookup_tables(vec![xor::lookup_table()])
        .setup()
        .prove_and_verify();
}

#[test]
// End-to-end test
fn test_prove_and_verify_xor() {
    prove_and_verify(64, XOR); // test XOR
}

#[test]
// End-to-end test
fn test_prove_and_verify_not() {
    prove_and_verify(64, NOT); // test NOT
}

#[test]
// Test a XOR of 64bit whose output is all ones with alternating inputs
fn test_xor64_alternating() {
    let input1 = BigUint::from(6510615555426900570u64);
    let input2 = BigUint::from(11936128518282651045u64);
    let witness = test_xor(&input1, &input2, Some(64));
    assert_eq!(witness[2][0], PallasField::from(2u128.pow(64) - 1));
    assert_eq!(witness[2][1], PallasField::from(2u64.pow(48) - 1));
    assert_eq!(witness[2][2], PallasField::from(2u64.pow(32) - 1));
    assert_eq!(witness[2][3], PallasField::from(2u32.pow(16) - 1));
    assert_eq!(witness[2][4], PallasField::from(0));
    check_xor(&witness, 64, &input1, &input2);
}

#[test]
// Test a XOR of 64bit whose inputs are zero. Checks it works fine with non-dense values.
fn test_xor64_zeros() {
    // forces zero to fit in 64 bits even if it only needs 1 bit
    let zero = BigUint::from(0u32);
    let witness = test_xor(&zero, &zero, Some(64));
    assert_eq!(witness[2][0], PallasField::from(0));
    check_xor(&witness, 64, &zero, &zero);
}

#[test]
// Test a XOR of 64bit whose inputs are all zero and all one. Checks it works fine with non-dense values.
fn test_xor64_zero_one() {
    let zero = BigUint::from(0u32);
    let all_ones = all_ones(64);
    let witness = test_xor(&zero, &all_ones, None);
    assert_eq!(witness[2][0], PallasField::from(all_ones.clone()));
    check_xor(&witness, 64, &zero, &all_ones);
}

#[test]
// Tests a XOR of 8 bits for a random input
fn test_xor8_random() {
    let input1 = big_random(8);
    let input2 = big_random(8);
    let witness = test_xor(&input1, &input2, Some(8));
    check_xor(&witness, 8, &input1, &input2);
}

#[test]
// Tests a XOR of 16 bits for a random input
fn test_xor16_random() {
    let input1 = big_random(16);
    let input2 = big_random(16);
    let witness = test_xor(&input1, &input2, Some(16));
    check_xor(&witness, 16, &input1, &input2);
}

#[test]
// Tests a XOR of 32 bits for a random input
fn test_xor32_random() {
    let input1 = big_random(32);
    let input2 = big_random(32);
    let witness = test_xor(&input1, &input2, Some(32));
    check_xor(&witness, 32, &input1, &input2);
}

#[test]
// Tests a XOR of 64 bits for a random input
fn test_xor64_random() {
    let input1 = big_random(64);
    let input2 = big_random(64);
    let witness = test_xor(&input1, &input2, Some(64));
    check_xor(&witness, 64, &input1, &input2);
}

#[test]
// Test a random XOR of 128 bits
fn test_xor128_random() {
    let input1 = big_random(128);
    let input2 = big_random(128);
    let witness = test_xor(&input1, &input2, Some(128));
    check_xor(&witness, 128, &input1, &input2);
}

#[test]
// Tests all possible 16 values for a crumb, for both full 4, 8, 12, and 16 bits, and smallest
fn test_not_all_crumb() {
    for i in 0..2u8.pow(4) {
        let input = BigUint::from(i);
        let witness = test_not(&input, None);
        check_not(&witness, &input, None);
        for c in (4..=16).step_by(4) {
            let bits = Some(c);
            let witness = test_not(&input, bits);
            check_not(&witness, &input, bits);
        }
    }
}

#[test]
// Tests NOT for bitlengths of 4, 8, 16, 32, 64, 128, for both exact output width and varying
fn test_not_crumbs_random() {
    for i in 2..=7 {
        let bits = Some(2u32.pow(i));
        let input = big_random(bits.unwrap());
        let witness_full = test_not(&input, bits);
        check_not(&witness_full, &input, bits);
        let witness_partial = test_not(&input, None);
        check_not(&witness_partial, &input, None);
    }
}

#[test]
// Tests a NOT for a random-length big input
fn test_not_big_random() {
    let input = big_random(200);
    let witness = test_not(&input, None);
    check_not(&witness, &input, None);
}

#[test]
// Tests two NOTs with the generic builder
fn test_not_generic_double() {
    let input1 = big_random(64);
    let input2 = big_random(64);
    let witness = test_not_gnrc(&input1, &Some(input2.clone()), 64);
    assert_eq!(witness[2][1], PallasField::from(big_not(&input1, Some(64))));
    assert_eq!(witness[5][1], PallasField::from(big_not(&input2, Some(64))));
}

#[test]
// Tests one NOT with the generic builder
fn test_not_generic_single() {
    let input = big_random(64);
    let witness = test_not_gnrc(&input, &None, 64);
    assert_eq!(witness[2][1], PallasField::from(big_not(&input, Some(64))));
}
