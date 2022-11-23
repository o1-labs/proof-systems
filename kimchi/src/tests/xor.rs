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
use num_bigint::{BigUint, RandBigInt};
use o1_utils::{big_bits, big_xor, FieldFromBig, FieldHelpers};
use rand::{rngs::StdRng, SeedableRng};

use super::framework::TestFramework;

type PallasField = <Pallas as AffineCurve>::BaseField;

const XOR: bool = true;

const RNG_SEED: [u8; 32] = [
    211, 31, 143, 75, 29, 255, 0, 126, 237, 193, 86, 160, 1, 90, 131, 221, 186, 168, 4, 95, 50, 48,
    89, 29, 13, 250, 215, 172, 130, 24, 164, 162,
];

fn create_test_constraint_system_xor(bits: usize) -> ConstraintSystem<Fp> {
    let (mut next_row, mut gates) = CircuitGate::<Fp>::create_xor_gadget(0, bits);

    // Temporary workaround for lookup-table/domain-size issue
    for _ in 0..(1 << 13) {
        gates.push(CircuitGate::zero(Wire::for_row(next_row)));
        next_row += 1;
    }

    ConstraintSystem::create(gates).build().unwrap()
}

pub(crate) fn initialize(
    input: Option<PallasField>,
    bits: Option<usize>,
    rng: &mut StdRng,
) -> PallasField {
    if let Some(inp) = input {
        inp
    } else {
        assert!(bits.is_some());
        let bits = bits.unwrap();
        PallasField::from_biguint(
            &rng.gen_biguint_range(&BigUint::from(0u8), &BigUint::from(2u8).pow(bits as u32)),
        )
        .unwrap()
    }
}

// Returns the all ones BigUint of bits length
pub(crate) fn all_ones(bits: usize) -> PallasField {
    PallasField::from(2u128).pow(&[bits as u64]) - PallasField::one()
}

// Returns a given crumb of 4 bits
pub(crate) fn xor_crumb(word: BigUint, crumb: usize) -> BigUint {
    (word >> (4 * crumb)) % 2u128.pow(4)
}

// Manually checks the XOR of each crumb in the witness
pub(crate) fn check_xor(
    witness: &[Vec<PallasField>; COLUMNS],
    bits: usize,
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

// General test for Xor
fn test_xor(
    in1: Option<PallasField>,
    in2: Option<PallasField>,
    bits: Option<usize>,
) -> [Vec<PallasField>; COLUMNS] {
    let rng = &mut StdRng::from_seed(RNG_SEED);
    // Initalize inputs
    // If some input was given then use that one, otherwise generate a random one with the given bits
    let input1 = initialize(in1, bits, rng);
    let input2 = initialize(in2, bits, rng);

    // If user specified a concrete number of bits, use that (if they are sufficient to hold both inputs)
    // Otherwise, use the max number of bits required to hold both inputs (if only one, the other is zero)
    let bits1 = big_bits(&input1.to_biguint());
    let bits2 = big_bits(&input2.to_biguint());
    let bits = bits.map_or(0, |b| b); // 0 or bits
    let bits = max(bits, max(bits1, bits2));

    let cs = create_test_constraint_system_xor(bits);
    let witness = xor::create_xor_witness(input1, input2, bits);
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

    check_xor(&witness, bits, input1, input2, XOR);

    witness
}

#[test]
// End-to-end test of XOR
fn test_prove_and_verify_xor() {
    let rng = &mut StdRng::from_seed(RNG_SEED);

    let bits = 64;
    // Create
    let (mut next_row, mut gates) = CircuitGate::<Fp>::create_xor_gadget(0, bits);

    // Temporary workaround for lookup-table/domain-size issue
    for _ in 0..(1 << 13) {
        gates.push(CircuitGate::zero(Wire::for_row(next_row)));
        next_row += 1;
    }

    let input1 = PallasField::from_biguint(
        &rng.gen_biguint_range(&BigUint::from(0u8), &BigUint::from(2u8).pow(bits as u32)),
    )
    .unwrap();
    let input2 = PallasField::from_biguint(
        &rng.gen_biguint_range(&BigUint::from(0u8), &BigUint::from(2u8).pow(bits as u32)),
    )
    .unwrap();

    // Create witness and random inputs
    let witness = xor::create_xor_witness(input1, input2, bits);

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
    let witness = test_xor(Some(input1), Some(input2), Some(64));
    assert_eq!(witness[2][0], PallasField::from(2u128.pow(64) - 1));
    assert_eq!(witness[2][1], PallasField::from(2u64.pow(48) - 1));
    assert_eq!(witness[2][2], PallasField::from(2u64.pow(32) - 1));
    assert_eq!(witness[2][3], PallasField::from(2u32.pow(16) - 1));
    assert_eq!(witness[2][4], PallasField::from(0));
}

#[test]
// Test a XOR of 64bit whose inputs are zero. Checks it works fine with non-dense values.
fn test_xor64_zeros() {
    // forces zero to fit in 64 bits even if it only needs 1 bit
    let zero = PallasField::from_biguint(&BigUint::from(0u32)).unwrap();
    let witness = test_xor(Some(zero), Some(zero), Some(64));
    assert_eq!(witness[2][0], PallasField::from(0));
}

#[test]
// Test a XOR of 64bit whose inputs are all zero and all one. Checks it works fine with non-dense values.
fn test_xor64_zero_one() {
    let zero = PallasField::from_biguint(&BigUint::from(0u32)).unwrap();
    let all_ones = all_ones(64);
    let witness = test_xor(Some(zero), Some(all_ones), None);
    assert_eq!(witness[2][0], all_ones);
}

#[test]
// Tests a XOR of 8 bits for a random input
fn test_xor8_random() {
    test_xor(None, None, Some(8));
}

#[test]
// Tests a XOR of 16 bits for a random input
fn test_xor16_random() {
    test_xor(None, None, Some(16));
}

#[test]
// Tests a XOR of 32 bits for a random input
fn test_xor32_random() {
    test_xor(None, None, Some(32));
}

#[test]
// Tests a XOR of 64 bits for a random input
fn test_xor64_random() {
    test_xor(None, None, Some(64));
}

#[test]
// Test a random XOR of 128 bits
fn test_xor128_random() {
    test_xor(None, None, Some(128));
}
