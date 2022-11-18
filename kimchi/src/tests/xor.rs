use std::{array, cmp::max};

use crate::circuits::{
    constraints::ConstraintSystem,
    gate::CircuitGate,
    polynomial::COLUMNS,
    polynomials::{
        generic::GenericGateSpec,
        xor::{self},
    },
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

const NOT: bool = false;
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

fn create_test_constraint_system_not_xor(bits: u32) -> ConstraintSystem<Fp> {
    let (mut next_row, mut gates) = {
        let mut gates = vec![CircuitGate::<Fp>::create_generic_gadget(
            Wire::for_row(0),
            GenericGateSpec::Pub,
            None,
        )];
        let next_row = CircuitGate::<Fp>::extend_not_xor_gadget(&mut gates, 0, 1, bits);
        (next_row, gates)
    };

    // Temporary workaround for lookup-table/domain-size issue
    for _ in 0..(1 << 13) {
        gates.push(CircuitGate::zero(Wire::for_row(next_row)));
        next_row += 1;
    }

    ConstraintSystem::create(gates).build().unwrap()
}

fn create_test_constraint_system_not_gnrc(nots: usize) -> ConstraintSystem<Fp> {
    let mut gates = vec![CircuitGate::<Fp>::create_generic_gadget(
        Wire::for_row(0),
        GenericGateSpec::Pub,
        None,
    )];
    let mut next_row = CircuitGate::<Fp>::extend_not_gnrc_gadget(&mut gates, nots, 0, 1);

    // Temporary workaround for lookup-table/domain-size issue
    for _ in 0..(1 << 13) {
        gates.push(CircuitGate::zero(Wire::for_row(next_row)));
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

fn not_xor_witness(inp: &BigUint, bits: u32) -> [Vec<PallasField>; COLUMNS] {
    // Set up the initial public input to all ones
    let mut witness = array::from_fn(|_| vec![PallasField::from(0u32); 1]);
    witness[0][0] = PallasField::from(2u32).pow(&[bits as u64]) - PallasField::one();

    let mut not_witness = xor::create_not_xor_witness(inp, Some(bits));

    for col in 0..COLUMNS {
        witness[col].append(&mut not_witness[col]);
    }

    witness
}

// Tester for not gate
fn test_not_xor(inp: &BigUint, bits: Option<u32>) -> [Vec<PallasField>; COLUMNS] {
    // If user specified a concrete number of bits, use that (if they are sufficient to hold the input)
    // Otherwise, use the length of the input
    let bits = max(big_bits(&inp) as u32, bits.unwrap_or(0));

    let cs = create_test_constraint_system_not_xor(bits);

    let witness = not_xor_witness(inp, bits);

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

fn not_gnrc_witness(inputs: &Vec<BigUint>, bits: u32) -> [Vec<PallasField>; COLUMNS] {
    // Set up the initial public input to all ones
    let mut witness = array::from_fn(|_| vec![PallasField::from(0u32); 1]);
    witness[0][0] = PallasField::from(2u32).pow(&[bits as u64]) - PallasField::one();

    let mut not_witness = xor::create_not_gnrc_witness(inputs, bits);

    for col in 0..COLUMNS {
        witness[col].append(&mut not_witness[col]);
    }

    witness
}

// Tester for not gate generic
fn test_not_gnrc(inputs: &Vec<BigUint>, bits: u32) -> [Vec<PallasField>; COLUMNS] {
    let cs = create_test_constraint_system_not_gnrc(inputs.len());

    let witness = not_gnrc_witness(inputs, bits);

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
fn check_xor(
    witness: &[Vec<PallasField>; COLUMNS],
    bits: u32,
    input1: &BigUint,
    input2: &BigUint,
    not: bool,
) {
    let ini_row = if not == NOT { 1 } else { 0 };
    for x in 0..xor::num_xors(bits) {
        let in1 = (0..4)
            .map(|i| xor_crumb(input1, i + 4 * x))
            .collect::<Vec<BigUint>>();
        let in2 = (0..4)
            .map(|i| xor_crumb(input2, i + 4 * x))
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

// Manually checks the NOT of each crumb in the witness
fn check_not_xor(witness: &[Vec<PallasField>; COLUMNS], input: &BigUint, bits: Option<u32>) {
    let bits = max(big_bits(&input) as u32, bits.unwrap_or(0));
    check_xor(&witness, bits, &input, &all_ones(bits), NOT);
    assert_eq!(witness[2][1], PallasField::from(big_not(input, Some(bits))));
}

// Manually checks the NOTs of a vector of inputs in generic gates
fn check_not_gnrc(witness: &[Vec<PallasField>; COLUMNS], inputs: &Vec<BigUint>, bits: u32) {
    for (i, input) in inputs.iter().enumerate() {
        if i % 2 == 0 {
            assert_eq!(
                witness[2][1 + i / 2],
                PallasField::from(big_not(input, Some(bits)))
            );
        } else {
            assert_eq!(
                witness[5][1 + (i - 1) / 2],
                PallasField::from(big_not(input, Some(bits)))
            );
        }
    }
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
    let witness = xor::create_xor_witness(&big_random(bits), &big_random(bits), bits);

    TestFramework::default()
        .gates(gates)
        .witness(witness)
        .lookup_tables(vec![xor::lookup_table()])
        .setup()
        .prove_and_verify();
}

#[test]
// End-to-end test of NOT using XOR gadget
fn test_prove_and_verify_not_xor() {
    let bits = 64;
    // Create circuit
    let (mut next_row, mut gates) = {
        let mut gates = vec![CircuitGate::<Fp>::create_generic_gadget(
            Wire::for_row(0),
            GenericGateSpec::Pub,
            None,
        )];
        let next_row = CircuitGate::<Fp>::extend_not_xor_gadget(&mut gates, 0, 1, bits);
        (next_row, gates)
    };

    // Temporary workaround for lookup-table/domain-size issue
    for _ in 0..(1 << 13) {
        gates.push(CircuitGate::zero(Wire::for_row(next_row)));
        next_row += 1;
    }

    // Create witness and random inputs

    let witness = not_xor_witness(&big_random(bits), bits);

    TestFramework::default()
        .gates(gates)
        .witness(witness)
        .public_inputs(vec![
            PallasField::from(2u32).pow(&[bits as u64]) - PallasField::one(),
        ])
        .lookup_tables(vec![xor::lookup_table()])
        .setup()
        .prove_and_verify();
}

#[test]
// End-to-end test of NOT using generic gadget
fn test_prove_and_verify_one_not_gnrc() {
    let bits = 64;
    // Create circuit
    let (mut next_row, mut gates) = {
        let mut gates = vec![CircuitGate::<Fp>::create_generic_gadget(
            Wire::for_row(0),
            GenericGateSpec::Pub,
            None,
        )];
        let next_row = CircuitGate::<Fp>::extend_not_gnrc_gadget(&mut gates, 1, 0, 1);
        (next_row, gates)
    };

    // Temporary workaround for lookup-table/domain-size issue
    for _ in 0..(1 << 13) {
        gates.push(CircuitGate::zero(Wire::for_row(next_row)));
        next_row += 1;
    }

    // Create witness and random inputs
    let witness: [Vec<PallasField>; 15] = not_gnrc_witness(
        &vec![
            big_random(bits),
            big_random(bits),
            big_random(bits),
            big_random(bits),
            big_random(bits),
        ],
        bits,
    );

    TestFramework::default()
        .gates(gates)
        .witness(witness)
        .public_inputs(vec![
            PallasField::from(2u32).pow(&[bits as u64]) - PallasField::one(),
        ])
        .setup()
        .prove_and_verify();
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
    check_xor(&witness, 64, &input1, &input2, NOT);
}

#[test]
// Test a XOR of 64bit whose inputs are zero. Checks it works fine with non-dense values.
fn test_xor64_zeros() {
    // forces zero to fit in 64 bits even if it only needs 1 bit
    let zero = BigUint::from(0u32);
    let witness = test_xor(&zero, &zero, Some(64));
    assert_eq!(witness[2][0], PallasField::from(0));
    check_xor(&witness, 64, &zero, &zero, XOR);
}

#[test]
// Test a XOR of 64bit whose inputs are all zero and all one. Checks it works fine with non-dense values.
fn test_xor64_zero_one() {
    let zero = BigUint::from(0u32);
    let all_ones = all_ones(64);
    let witness = test_xor(&zero, &all_ones, None);
    assert_eq!(witness[2][0], PallasField::from(all_ones.clone()));
    check_xor(&witness, 64, &zero, &all_ones, XOR);
}

#[test]
// Tests a XOR of 8 bits for a random input
fn test_xor8_random() {
    let input1 = big_random(8);
    let input2 = big_random(8);
    let witness = test_xor(&input1, &input2, Some(8));
    check_xor(&witness, 8, &input1, &input2, XOR);
}

#[test]
// Tests a XOR of 16 bits for a random input
fn test_xor16_random() {
    let input1 = big_random(16);
    let input2 = big_random(16);
    let witness = test_xor(&input1, &input2, Some(16));
    check_xor(&witness, 16, &input1, &input2, XOR);
}

#[test]
// Tests a XOR of 32 bits for a random input
fn test_xor32_random() {
    let input1 = big_random(32);
    let input2 = big_random(32);
    let witness = test_xor(&input1, &input2, Some(32));
    check_xor(&witness, 32, &input1, &input2, XOR);
}

#[test]
// Tests a XOR of 64 bits for a random input
fn test_xor64_random() {
    let input1 = big_random(64);
    let input2 = big_random(64);
    let witness = test_xor(&input1, &input2, Some(64));
    check_xor(&witness, 64, &input1, &input2, XOR);
}

#[test]
// Test a random XOR of 128 bits
fn test_xor128_random() {
    let input1 = big_random(128);
    let input2 = big_random(128);
    let witness = test_xor(&input1, &input2, Some(128));
    check_xor(&witness, 128, &input1, &input2, XOR);
}

#[test]
// Tests all possible 16 values for a crumb, for both full 4, 8, 12, and 16 bits, and smallest
fn test_not_all_crumb() {
    for i in 0..2u8.pow(4) {
        let input = BigUint::from(i);
        let witness = test_not_xor(&input, None);
        check_not_xor(&witness, &input, None);
        for c in (4..=16).step_by(4) {
            let bits = Some(c);
            let witness = test_not_xor(&input, bits);
            check_not_xor(&witness, &input, bits);
        }
    }
}

#[test]
// Tests NOT for bitlengths of 4, 8, 16, 32, 64, 128, for both exact output width and varying
fn test_not_crumbs_random() {
    for i in 2..=7 {
        let bits = Some(2u32.pow(i));
        let input = big_random(bits.unwrap());
        let witness_full = test_not_xor(&input, bits);
        check_not_xor(&witness_full, &input, bits);
        let witness_partial = test_not_xor(&input, None);
        check_not_xor(&witness_partial, &input, None);
    }
}

#[test]
// Tests a NOT for a random-length big input
fn test_not_big_random() {
    let input = big_random(200);
    let witness = test_not_xor(&input, None);
    check_not_xor(&witness, &input, None);
}

#[test]
// Tests two NOTs with the generic builder
fn test_not_gnrc_double() {
    let input1 = big_random(64);
    let input2 = big_random(64);
    let witness = test_not_gnrc(&vec![input1.clone(), input2.clone()], 64);
    check_not_gnrc(&witness, &vec![input1, input2], 64);
}

#[test]
// Tests one NOT with the generic builder
fn test_not_gnrc_single() {
    let input = big_random(64);
    let witness = test_not_gnrc(&vec![input.clone()], 64);
    check_not_gnrc(&witness, &vec![input], 64);
}

#[test]
// Tests a chain of 5 NOTs with different lengths but padded to 254 bits with the generic builder
fn test_not_gnrc_vector() {
    let inputs = vec![
        big_random(16),
        big_random(32),
        big_random(64),
        big_random(128),
        big_random(254),
    ];
    let witness = test_not_gnrc(&inputs, 254);
    check_not_gnrc(&witness, &inputs, 254);
}
