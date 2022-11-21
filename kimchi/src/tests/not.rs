use std::{array, cmp::max};

use crate::{
    circuits::{
        constraints::ConstraintSystem,
        gate::CircuitGate,
        polynomial::COLUMNS,
        polynomials::{
            generic::GenericGateSpec,
            not,
            xor::{self},
        },
        wires::Wire,
    },
    tests::xor::{all_ones, check_xor},
};

use ark_ec::AffineCurve;
use ark_ff::{Field, One};
use mina_curves::pasta::{Fp, Pallas, Vesta};
use num_bigint::BigUint;
use o1_utils::{big_bit_ops::big_random, big_bits, big_not};

use super::framework::TestFramework;

type PallasField = <Pallas as AffineCurve>::BaseField;

const NOT: bool = false;

// Constraint system for Not gadget using Xor16
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

// Constraint system for Not gadget using generic gates
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

// Creates the witness for Not gadget using Xor16
fn not_xor_witness(inp: &BigUint, bits: u32) -> [Vec<PallasField>; COLUMNS] {
    // Set up the initial public input to all ones
    let mut witness = array::from_fn(|_| vec![PallasField::from(0u32); 1]);
    witness[0][0] = PallasField::from(2u32).pow(&[bits as u64]) - PallasField::one();

    let mut not_witness = not::create_not_xor_witness(inp, Some(bits));

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

// Creates the witness for Not gadget using generic gates
fn not_gnrc_witness(inputs: &Vec<BigUint>, bits: u32) -> [Vec<PallasField>; COLUMNS] {
    // Set up the initial public input to all ones
    let mut witness = array::from_fn(|_| vec![PallasField::from(0u32); 1]);
    witness[0][0] = PallasField::from(2u32).pow(&[bits as u64]) - PallasField::one();

    let mut not_witness = not::create_not_gnrc_witness(inputs, bits);

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
