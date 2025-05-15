use crate::{
    circuits::{
        constraints::ConstraintSystem,
        gate::{CircuitGate, CircuitGateError, GateType},
        polynomial::COLUMNS,
        polynomials::{generic::GenericGateSpec, not, xor},
        wires::Wire,
    },
    curve::KimchiCurve,
    prover_index::testing::new_index_for_test_with_lookups,
    tests::xor::{all_ones, check_xor},
};
use core::{array, cmp::max};

use super::framework::TestFramework;
use ark_ec::AffineRepr;
use ark_ff::{Field, One, PrimeField, Zero};
use mina_curves::pasta::{Fp, Pallas, Vesta, VestaParameters};
use mina_poseidon::{
    constants::PlonkSpongeConstantsKimchi,
    sponge::{DefaultFqSponge, DefaultFrSponge},
};
use num_bigint::BigUint;
use o1_utils::{BigUintHelpers, BitwiseOps, FieldHelpers, RandomField};
use poly_commitment::ipa::OpeningProof;
use std::sync::Arc;

type PallasField = <Pallas as AffineRepr>::BaseField;
type VestaField = <Vesta as AffineRepr>::BaseField;
type SpongeParams = PlonkSpongeConstantsKimchi;
type VestaBaseSponge = DefaultFqSponge<VestaParameters, SpongeParams>;
type VestaScalarSponge = DefaultFrSponge<Fp, SpongeParams>;

const NOT: bool = false;

// Creates as many negations as the number of inputs. The inputs must fit in the native field.
// We start at the row 0 using generic gates to perform the negations.
// Input: a vector of words to be negated, and the number of bits (all the same)
// Panics if the bits length is too small for the inputs
fn create_not_witness_unchecked_length<F: PrimeField>(
    inputs: &[F],
    bits: usize,
) -> [Vec<F>; COLUMNS] {
    let mut witness: [Vec<F>; COLUMNS] = array::from_fn(|_| vec![F::zero(); 1]);
    witness[0][0] = F::from(2u8).pow([bits as u64]) - F::one();
    let result = not::extend_not_witness_unchecked_length(&mut witness, inputs, bits);
    if let Err(e) = result {
        panic!("{}", e);
    }
    witness
}

// Create a Not witness for less than 255 bits (native field) starting at row 0
// Input: first input and optional bit length
// If `bits` is not provided, the negation is performed using the length of the `input` in bits.
// If `bits` is provided, the negation takes the maximum length of `bits` and `input`.
fn create_not_witness_checked_length<F: PrimeField>(
    input: F,
    bits: Option<usize>,
) -> [Vec<F>; COLUMNS] {
    let mut witness: [Vec<F>; COLUMNS] = array::from_fn(|_| vec![F::zero(); 1]);
    let input_big = input.to_biguint();
    let real_bits = max(input_big.bitlen(), bits.unwrap_or(0));
    witness[0][0] = F::from(2u8).pow([real_bits as u64]) - F::one();
    not::extend_not_witness_checked_length(&mut witness, input, bits);
    witness
}

// Constraint system for Not gadget using Xor16
fn create_test_constraint_system_not_xor<G: KimchiCurve>(
    bits: usize,
) -> ConstraintSystem<G::ScalarField>
where
    G::BaseField: PrimeField,
{
    let gates = {
        let mut gates = vec![CircuitGate::<G::ScalarField>::create_generic_gadget(
            Wire::for_row(0),
            GenericGateSpec::Pub,
            None,
        )];
        let _next_row =
            CircuitGate::<G::ScalarField>::extend_not_gadget_checked_length(&mut gates, 0, bits);
        gates
    };

    ConstraintSystem::create(gates).public(1).build().unwrap()
}

// Constraint system for Not gadget using generic gates
fn create_test_constraint_system_not_gnrc<G: KimchiCurve>(
    num_nots: usize,
) -> ConstraintSystem<G::ScalarField>
where
    G::BaseField: PrimeField,
{
    let mut gates = vec![CircuitGate::<G::ScalarField>::create_generic_gadget(
        Wire::for_row(0),
        GenericGateSpec::Pub,
        None,
    )];
    let _next_row =
        CircuitGate::<G::ScalarField>::extend_not_gadget_unchecked_length(&mut gates, num_nots, 0);

    ConstraintSystem::create(gates).public(1).build().unwrap()
}

// Creates the witness and circuit for NOT gadget using XOR
fn setup_not_xor<G: KimchiCurve>(
    input: Option<G::ScalarField>,
    bits: Option<usize>,
) -> (
    [Vec<G::ScalarField>; COLUMNS],
    ConstraintSystem<G::ScalarField>,
)
where
    G::BaseField: PrimeField,
{
    let rng = &mut o1_utils::tests::make_test_rng(None);

    let input = rng.gen(input, bits);

    // If user specified a concrete number of bits, use that (if they are sufficient to hold the input)
    // Otherwise, use the length of the input
    let bits_real = max(input.to_biguint().bitlen(), bits.unwrap_or(0));

    let cs = create_test_constraint_system_not_xor::<G>(bits_real);

    let witness = create_not_witness_checked_length::<G::ScalarField>(input, bits);

    check_not_xor::<G>(&witness, input, bits);

    (witness, cs)
}

// Tester for not gate
fn test_not_xor<G: KimchiCurve>(
    input: Option<G::ScalarField>,
    bits: Option<usize>,
) -> [Vec<G::ScalarField>; COLUMNS]
where
    G::BaseField: PrimeField,
{
    let (witness, cs) = setup_not_xor::<G>(input, bits);

    for row in 0..witness[0].len() {
        assert_eq!(
            cs.gates[row].verify_witness::<G>(row, &witness, &cs, &witness[0][0..cs.public]),
            Ok(())
        );
    }

    witness
}

// Creates the witness and circuit for NOT gadget using generic
fn setup_not_gnrc<G: KimchiCurve>(
    inputs: Option<Vec<G::ScalarField>>,
    bits: usize,
    len: Option<usize>,
) -> (
    [Vec<G::ScalarField>; COLUMNS],
    ConstraintSystem<G::ScalarField>,
)
where
    G::BaseField: PrimeField,
{
    let rng = &mut o1_utils::tests::make_test_rng(None);

    let inputs = if let Some(inps) = inputs {
        assert!(len.is_none());
        inps
    } else {
        assert!(len.is_some());
        let len = len.unwrap();
        (0..len)
            .map(|_| rng.gen_field_with_bits(bits))
            .collect::<Vec<G::ScalarField>>()
    };

    let cs = create_test_constraint_system_not_gnrc::<G>(inputs.len());

    let witness = create_not_witness_unchecked_length::<G::ScalarField>(&inputs, bits);

    check_not_gnrc::<G>(&witness, &inputs, bits);

    (witness, cs)
}

// Tester for not gate generic
fn test_not_gnrc<G: KimchiCurve>(
    inputs: Option<Vec<G::ScalarField>>,
    bits: usize,
    len: Option<usize>,
) -> [Vec<G::ScalarField>; COLUMNS]
where
    G::BaseField: PrimeField,
{
    let (witness, cs) = setup_not_gnrc::<G>(inputs, bits, len);

    // test public input and not generic gate
    for row in 0..witness[0].len() {
        assert_eq!(
            cs.gates[row].verify_witness::<G>(row, &witness, &cs, &witness[0][0..cs.public]),
            Ok(())
        );
    }

    witness
}

// Manually checks the NOT of each crumb in the witness
fn check_not_xor<G: KimchiCurve>(
    witness: &[Vec<G::ScalarField>; COLUMNS],
    input: G::ScalarField,
    bits: Option<usize>,
) {
    let input_big = input.to_biguint();
    let bits = max(input_big.bitlen(), bits.unwrap_or(0));
    check_xor::<G>(witness, bits, input, all_ones::<G>(bits), NOT);
    assert_eq!(
        witness[2][1],
        BigUint::bitwise_not(&input_big, Some(bits)).into()
    );
}

// Manually checks the NOTs of a vector of inputs in generic gates
fn check_not_gnrc<G: KimchiCurve>(
    witness: &[Vec<G::ScalarField>; COLUMNS],
    inputs: &[G::ScalarField],
    bits: usize,
) {
    for (i, input) in inputs.iter().enumerate() {
        let input = input.to_biguint();
        if i % 2 == 0 {
            assert_eq!(
                witness[2][1 + i / 2],
                BigUint::bitwise_not(&input, Some(bits)).into()
            );
        } else {
            assert_eq!(
                witness[5][1 + (i - 1) / 2],
                BigUint::bitwise_not(&input, Some(bits)).into()
            );
        }
    }
}

#[test]
// End-to-end test of NOT using XOR gadget
fn test_prove_and_verify_not_xor() {
    let bits = 64;
    let rng = &mut o1_utils::tests::make_test_rng(None);

    // Create circuit
    let gates = {
        let mut gates = vec![CircuitGate::<Fp>::create_generic_gadget(
            Wire::for_row(0),
            GenericGateSpec::Pub,
            None,
        )];
        let _next_row = CircuitGate::<Fp>::extend_not_gadget_checked_length(&mut gates, 0, bits);
        gates
    };

    // Create witness and random inputs

    let witness =
        create_not_witness_checked_length::<PallasField>(rng.gen_field_with_bits(bits), Some(bits));

    TestFramework::<Vesta>::default()
        .gates(gates)
        .witness(witness)
        .public_inputs(vec![
            PallasField::from(2u32).pow([bits as u64]) - PallasField::one(),
        ])
        .setup()
        .prove_and_verify::<VestaBaseSponge, VestaScalarSponge>()
        .unwrap();
}

#[test]
// End-to-end test of NOT using generic gadget
fn test_prove_and_verify_five_not_gnrc() {
    let bits = 64;
    let rng = &mut o1_utils::tests::make_test_rng(None);

    // Create circuit
    let gates = {
        let mut gates = vec![CircuitGate::<Fp>::create_generic_gadget(
            Wire::for_row(0),
            GenericGateSpec::Pub,
            None,
        )];
        let _next_row = CircuitGate::<Fp>::extend_not_gadget_unchecked_length(&mut gates, 5, 0);
        gates
    };

    // Create witness and random inputs
    let witness: [Vec<PallasField>; 15] = create_not_witness_unchecked_length::<PallasField>(
        &(0..5)
            .map(|_| rng.gen_field_with_bits(bits))
            .collect::<Vec<PallasField>>(),
        bits,
    );

    TestFramework::<Vesta>::default()
        .gates(gates)
        .witness(witness)
        .public_inputs(vec![
            PallasField::from(2u32).pow([bits as u64]) - PallasField::one(),
        ])
        .setup()
        .prove_and_verify::<VestaBaseSponge, VestaScalarSponge>()
        .unwrap();
}

#[test]
// Tests all possible 16 values for a crumb, for both full 4, 8, 12, and 16 bits, and smallest
fn test_not_xor_all_crumb() {
    for i in 0..2u8.pow(4) {
        let input = PallasField::from(i);
        test_not_xor::<Vesta>(Some(input), None);
        for c in (4..=16).step_by(4) {
            let bits = Some(c);
            test_not_xor::<Vesta>(Some(input), bits);
        }
    }
}

#[test]
// Tests NOT for bitlengths of 4, 8, 16, 32, 64, 128, for both exact output width and varying
fn test_not_xor_crumbs_random() {
    for i in 2..=7 {
        let bits = 2u32.pow(i) as usize;
        let rng = &mut o1_utils::tests::make_test_rng(None);
        let input = rng.gen_field_with_bits(bits);
        test_not_xor::<Vesta>(Some(input), Some(bits));
        test_not_xor::<Vesta>(Some(input), None);
    }
}

#[test]
// Tests a NOT for a random-length big input
fn test_not_xor_big_random() {
    let rng = &mut o1_utils::tests::make_test_rng(None);
    let input = rng.gen_field_with_bits(200);
    test_not_xor::<Vesta>(Some(input), None);
    let input = rng.gen_field_with_bits(200);
    test_not_xor::<Pallas>(Some(input), None);
}

#[test]
// Tests two NOTs with the generic builder
fn test_not_gnrc_double() {
    test_not_gnrc::<Vesta>(None, 64, Some(2));
    test_not_gnrc::<Pallas>(None, 64, Some(2));
}

#[test]
// Tests one NOT with the generic builder
fn test_not_gnrc_single() {
    test_not_gnrc::<Vesta>(None, 64, Some(1));
    test_not_gnrc::<Pallas>(None, 64, Some(1));
}

#[test]
// Tests a chain of 5 NOTs with different lengths but padded to 254 bits with the generic builder
fn test_not_gnrc_vector() {
    let rng = &mut o1_utils::tests::make_test_rng(None);
    // up to 2^16, 2^32, 2^64, 2^128, 2^254
    let inputs = (0..5)
        .map(|i| rng.gen_field_with_bits(4 + i))
        .collect::<Vec<PallasField>>();
    test_not_gnrc::<Vesta>(Some(inputs), 254, None);
    let inputs = (0..5)
        .map(|i| rng.gen_field_with_bits(4 + i))
        .collect::<Vec<VestaField>>();
    test_not_gnrc::<Pallas>(Some(inputs), 254, None);
}

#[test]
// Test a bad NOT with gnrc builder
fn test_bad_not_gnrc() {
    let (mut witness, cs) = setup_not_gnrc::<Vesta>(None, 64, Some(1));
    // modify public input row to make sure the copy constraint fails and the generic gate also fails
    witness[0][0] += PallasField::one();
    assert_eq!(
        cs.gates[0].verify_witness::<Vesta>(0, &witness, &cs, &witness[0][0..cs.public]),
        Err(CircuitGateError::CopyConstraint {
            typ: GateType::Generic,
            src: Wire { row: 0, col: 0 },
            dst: Wire { row: 1, col: 0 }
        })
    );
    witness[0][1] += PallasField::one();
    let index = new_index_for_test_with_lookups(
        Arc::try_unwrap(cs.gates).unwrap(),
        1,
        0,
        vec![xor::lookup_table()],
        None,
        false,
        None,
        false,
    );
    assert_eq!(
        index.cs.gates[1].verify::<Vesta, OpeningProof<Vesta>>(1, &witness, &index, &[]),
        Err(("generic: incorrect gate").to_string())
    );
}

#[test]
// Test a bad NOT with XOR builder
fn test_bad_not_xor() {
    let (mut witness, cs) = setup_not_xor::<Vesta>(None, Some(16));
    // modify public input row to make sure the copy constraint fails and the XOR gate also fails
    witness[0][0] += PallasField::one();
    assert_eq!(
        cs.gates[0].verify_witness::<Vesta>(0, &witness, &cs, &witness[0][0..cs.public]),
        Err(CircuitGateError::CopyConstraint {
            typ: GateType::Generic,
            src: Wire { row: 0, col: 0 },
            dst: Wire { row: 1, col: 1 }
        })
    );
    witness[1][1] += PallasField::one();
    // decomposition of xor fails
    assert_eq!(
        cs.gates[1].verify_witness::<Vesta>(1, &witness, &cs, &witness[0][0..cs.public]),
        Err(CircuitGateError::Constraint(GateType::Xor16, 2))
    );
    // Make the second input zero with correct decomposition to make sure XOR table fails
    witness[0][0] = PallasField::zero();
    witness[1][1] = PallasField::zero();
    witness[7][1] = PallasField::zero();
    witness[8][1] = PallasField::zero();
    witness[9][1] = PallasField::zero();
    witness[10][1] = PallasField::zero();

    assert_eq!(
        TestFramework::<Vesta>::default()
            .gates(Arc::try_unwrap(cs.gates).unwrap())
            .witness(witness)
            .setup()
            .prove_and_verify::<VestaBaseSponge, VestaScalarSponge>(),
        Err(String::from(
            "the lookup failed to find a match in the table: row=1"
        ))
    );
}
