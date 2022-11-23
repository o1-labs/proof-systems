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
    tests::xor::{all_ones, check_xor, random_field},
};

use super::{framework::TestFramework, xor::initialize};
use ark_ec::AffineCurve;
use ark_ff::{Field, One};
use mina_curves::pasta::{Fp, Pallas, Vesta};
use num_bigint::{BigUint, RandBigInt};
use o1_utils::{big_bits, big_not, FieldFromBig, FieldHelpers};
use rand::{rngs::StdRng, SeedableRng};

type PallasField = <Pallas as AffineCurve>::BaseField;

const NOT: bool = false;

const RNG_SEED: [u8; 32] = [
    211, 31, 143, 75, 29, 255, 0, 126, 237, 193, 86, 160, 1, 90, 131, 221, 186, 168, 4, 95, 50, 48,
    89, 29, 13, 250, 215, 172, 130, 24, 164, 162,
];

// Constraint system for Not gadget using Xor16
fn create_test_constraint_system_not_xor(bits: usize) -> ConstraintSystem<Fp> {
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
fn not_xor_witness(inp: PallasField, bits: usize) -> [Vec<PallasField>; COLUMNS] {
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
fn test_not_xor(inp: Option<PallasField>, bits: Option<usize>) -> [Vec<PallasField>; COLUMNS] {
    let rng = &mut StdRng::from_seed(RNG_SEED);

    let inp = initialize(inp, bits, rng);

    // If user specified a concrete number of bits, use that (if they are sufficient to hold the input)
    // Otherwise, use the length of the input
    let bits_real = max(big_bits(&inp.to_biguint()), bits.unwrap_or(0));

    let cs = create_test_constraint_system_not_xor(bits_real);

    let witness = not_xor_witness(inp, bits_real);

    for row in 0..xor::num_xors(bits_real) + 1 {
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

    check_not_xor(&witness, inp, bits);

    witness
}

// Creates the witness for Not gadget using generic gates
fn not_gnrc_witness(inputs: &Vec<PallasField>, bits: usize) -> [Vec<PallasField>; COLUMNS] {
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
fn test_not_gnrc(
    inputs: Option<Vec<PallasField>>,
    bits: usize,
    len: Option<usize>,
) -> [Vec<PallasField>; COLUMNS] {
    let rng = &mut StdRng::from_seed(RNG_SEED);

    let inputs = if let Some(inps) = inputs {
        assert!(len.is_none());
        inps
    } else {
        assert!(len.is_some());
        let len = len.unwrap();
        (0..len)
            .map(|_| random_field(bits, rng))
            .collect::<Vec<PallasField>>()
    };

    let cs = create_test_constraint_system_not_gnrc(inputs.len());

    let witness = not_gnrc_witness(&inputs, bits);

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

    check_not_gnrc(&witness, &inputs, bits);

    witness
}

// Manually checks the NOT of each crumb in the witness
fn check_not_xor(witness: &[Vec<PallasField>; COLUMNS], input: PallasField, bits: Option<usize>) {
    let input_big = input.to_biguint();
    let bits = max(big_bits(&input_big), bits.unwrap_or(0));
    check_xor(&witness, bits, input, all_ones(bits), NOT);
    assert_eq!(
        witness[2][1],
        PallasField::from(big_not(&input_big, Some(bits)))
    );
}

// Manually checks the NOTs of a vector of inputs in generic gates
fn check_not_gnrc(witness: &[Vec<PallasField>; COLUMNS], inputs: &Vec<PallasField>, bits: usize) {
    for (i, input) in inputs.iter().enumerate() {
        let input = input.to_biguint();
        if i % 2 == 0 {
            assert_eq!(
                witness[2][1 + i / 2],
                PallasField::from(big_not(&input, Some(bits)))
            );
        } else {
            assert_eq!(
                witness[5][1 + (i - 1) / 2],
                PallasField::from(big_not(&input, Some(bits)))
            );
        }
    }
}

#[test]
// End-to-end test of NOT using XOR gadget
fn test_prove_and_verify_not_xor() {
    let bits = 64;
    let rng = &mut StdRng::from_seed(RNG_SEED);

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

    let witness = not_xor_witness(
        PallasField::from_biguint(
            &rng.gen_biguint_range(&BigUint::from(0u8), &BigUint::from(2u8).pow(bits as u32)),
        )
        .unwrap(),
        bits,
    );

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
fn test_prove_and_verify_five_not_gnrc() {
    let bits = 64;
    let rng = &mut StdRng::from_seed(RNG_SEED);

    // Create circuit
    let (mut next_row, mut gates) = {
        let mut gates = vec![CircuitGate::<Fp>::create_generic_gadget(
            Wire::for_row(0),
            GenericGateSpec::Pub,
            None,
        )];
        let next_row = CircuitGate::<Fp>::extend_not_gnrc_gadget(&mut gates, 5, 0, 1);
        (next_row, gates)
    };

    // Temporary workaround for lookup-table/domain-size issue
    for _ in 0..(1 << 13) {
        gates.push(CircuitGate::zero(Wire::for_row(next_row)));
        next_row += 1;
    }

    // Create witness and random inputs
    let witness: [Vec<PallasField>; 15] =
        not_gnrc_witness(
            &(0..5)
                .map(|_| {
                    PallasField::from_biguint(&rng.gen_biguint_range(
                        &BigUint::from(0u8),
                        &BigUint::from(2u8).pow(bits as u32),
                    ))
                    .unwrap()
                })
                .collect::<Vec<PallasField>>(),
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
fn test_not_xor_all_crumb() {
    for i in 0..2u8.pow(4) {
        let input = PallasField::from(i);
        test_not_xor(Some(input), None);
        for c in (4..=16).step_by(4) {
            let bits = Some(c);
            test_not_xor(Some(input), bits);
        }
    }
}

#[test]
// Tests NOT for bitlengths of 4, 8, 16, 32, 64, 128, for both exact output width and varying
fn test_not_xor_crumbs_random() {
    for i in 2..=7 {
        let bits = 2u32.pow(i) as usize;
        let rng = &mut StdRng::from_seed(RNG_SEED);
        let input = PallasField::from_biguint(
            &rng.gen_biguint_range(&BigUint::from(0u8), &BigUint::from(2u8).pow(bits as u32)),
        )
        .unwrap();
        test_not_xor(Some(input), Some(bits));
        test_not_xor(Some(input), None);
    }
}

#[test]
// Tests a NOT for a random-length big input
fn test_not_xor_big_random() {
    let rng = &mut StdRng::from_seed(RNG_SEED);
    let input = PallasField::from_biguint(
        &rng.gen_biguint_range(&BigUint::from(0u8), &BigUint::from(2u8).pow(200)),
    )
    .unwrap();
    test_not_xor(Some(input), None);
}

#[test]
// Tests two NOTs with the generic builder
fn test_not_gnrc_double() {
    test_not_gnrc(None, 64, Some(2));
}

#[test]
// Tests one NOT with the generic builder
fn test_not_gnrc_single() {
    test_not_gnrc(None, 64, Some(1));
}

#[test]
// Tests a chain of 5 NOTs with different lengths but padded to 254 bits with the generic builder
fn test_not_gnrc_vector() {
    let rng = &mut StdRng::from_seed(RNG_SEED);
    // up to 2^16, 2^32, 2^64, 2^128, 2^254
    let inputs = (0..5)
        .map(|i| {
            PallasField::from_biguint(
                &rng.gen_biguint_range(&BigUint::from(0u8), &BigUint::from(2u8).pow(4 + i)),
            )
            .unwrap()
        })
        .collect::<Vec<PallasField>>();
    test_not_gnrc(Some(inputs), 254, None);
}
