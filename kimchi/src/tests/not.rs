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
    curve::KimchiCurve,
    plonk_sponge::FrSponge,
    tests::xor::{all_ones, check_xor, random_field},
};

use super::{framework::TestFramework, xor::initialize};
use ark_ec::AffineCurve;
use ark_ff::{Field, One, PrimeField};
use mina_curves::pasta::{Fp, Fq, Pallas, PallasParameters, Vesta, VestaParameters};
use mina_poseidon::{
    constants::PlonkSpongeConstantsKimchi,
    sponge::{DefaultFqSponge, DefaultFrSponge},
    FqSponge,
};
use num_bigint::BigUint;
use o1_utils::{big_bits, BitOps, FieldHelpers};
use rand::{rngs::StdRng, SeedableRng};

type PallasField = <Pallas as AffineCurve>::BaseField;
type VestaField = <Vesta as AffineCurve>::BaseField;
type SpongeParams = PlonkSpongeConstantsKimchi;
type VestaBaseSponge = DefaultFqSponge<VestaParameters, SpongeParams>;
type VestaScalarSponge = DefaultFrSponge<Fp, SpongeParams>;
type PallasBaseSponge = DefaultFqSponge<PallasParameters, SpongeParams>;
type PallasScalarSponge = DefaultFrSponge<Fq, SpongeParams>;

const NOT: bool = false;

const RNG_SEED: [u8; 32] = [
    211, 31, 143, 75, 29, 255, 0, 126, 237, 193, 86, 160, 1, 90, 131, 221, 186, 168, 4, 95, 50, 48,
    89, 29, 13, 250, 215, 172, 130, 24, 164, 162,
];

// Constraint system for Not gadget using Xor16
fn create_test_constraint_system_not_xor<G: KimchiCurve, EFqSponge, EFrSponge>(
    bits: usize,
) -> ConstraintSystem<G::ScalarField>
where
    G::BaseField: PrimeField,
{
    let (mut next_row, mut gates) = {
        let mut gates = vec![CircuitGate::<G::ScalarField>::create_generic_gadget(
            Wire::for_row(0),
            GenericGateSpec::Pub,
            None,
        )];
        let next_row = CircuitGate::<G::ScalarField>::extend_not_xor_gadget(&mut gates, 0, 1, bits);
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
fn create_test_constraint_system_not_gnrc<G: KimchiCurve, EFqSponge, EFrSponge>(
    nots: usize,
) -> ConstraintSystem<G::ScalarField>
where
    G::BaseField: PrimeField,
{
    let mut gates = vec![CircuitGate::<G::ScalarField>::create_generic_gadget(
        Wire::for_row(0),
        GenericGateSpec::Pub,
        None,
    )];
    let mut next_row =
        CircuitGate::<G::ScalarField>::extend_not_gnrc_gadget(&mut gates, nots, 0, 1);

    // Temporary workaround for lookup-table/domain-size issue
    for _ in 0..(1 << 13) {
        gates.push(CircuitGate::zero(Wire::for_row(next_row)));
        next_row += 1;
    }

    ConstraintSystem::create(gates).build().unwrap()
}

// Creates the witness for Not gadget using Xor16
fn not_xor_witness<G: KimchiCurve>(
    inp: G::ScalarField,
    bits: usize,
) -> [Vec<G::ScalarField>; COLUMNS] {
    // Set up the initial public input to all ones
    let mut witness = array::from_fn(|_| vec![G::ScalarField::from(0u32); 1]);
    witness[0][0] = G::ScalarField::from(2u32).pow(&[bits as u64]) - G::ScalarField::one();

    let mut not_witness = not::create_not_xor_witness(inp, Some(bits));

    for col in 0..COLUMNS {
        witness[col].append(&mut not_witness[col]);
    }

    witness
}

// Tester for not gate
fn test_not_xor<G: KimchiCurve, EFqSponge, EFrSponge>(
    inp: Option<G::ScalarField>,
    bits: Option<usize>,
) -> [Vec<G::ScalarField>; COLUMNS]
where
    G::BaseField: PrimeField,
    EFqSponge: Clone + FqSponge<G::BaseField, G, G::ScalarField>,
    EFrSponge: FrSponge<G::ScalarField>,
{
    let rng = &mut StdRng::from_seed(RNG_SEED);

    let inp = initialize::<G>(inp, bits, rng);

    // If user specified a concrete number of bits, use that (if they are sufficient to hold the input)
    // Otherwise, use the length of the input
    let bits_real = max(big_bits(&inp.to_biguint()), bits.unwrap_or(0));

    let cs = create_test_constraint_system_not_xor::<G, EFqSponge, EFrSponge>(bits_real);

    let witness = not_xor_witness::<G>(inp, bits_real);

    for row in 0..xor::num_xors(bits_real) + 1 {
        assert_eq!(
            cs.gates[row].verify_witness::<G>(
                row,
                &witness,
                &cs,
                &witness[0][0..cs.public].to_vec()
            ),
            Ok(())
        );
    }

    check_not_xor::<G>(&witness, inp, bits);

    witness
}

// Creates the witness for Not gadget using generic gates
fn not_gnrc_witness<G: KimchiCurve>(
    inputs: &Vec<G::ScalarField>,
    bits: usize,
) -> [Vec<G::ScalarField>; COLUMNS]
where
    G::BaseField: PrimeField,
{
    // Set up the initial public input to all ones
    let mut witness = array::from_fn(|_| vec![G::ScalarField::from(0u32); 1]);
    witness[0][0] = G::ScalarField::from(2u32).pow(&[bits as u64]) - G::ScalarField::one();

    let mut not_witness = not::create_not_gnrc_witness(inputs, bits);

    for col in 0..COLUMNS {
        witness[col].append(&mut not_witness[col]);
    }

    witness
}

// Tester for not gate generic
fn test_not_gnrc<G: KimchiCurve, EFqSponge, EFrSponge>(
    inputs: Option<Vec<G::ScalarField>>,
    bits: usize,
    len: Option<usize>,
) -> [Vec<G::ScalarField>; COLUMNS]
where
    G::BaseField: PrimeField,
    EFqSponge: Clone + FqSponge<G::BaseField, G, G::ScalarField>,
    EFrSponge: FrSponge<G::ScalarField>,
{
    let rng = &mut StdRng::from_seed(RNG_SEED);

    let inputs = if let Some(inps) = inputs {
        assert!(len.is_none());
        inps
    } else {
        assert!(len.is_some());
        let len = len.unwrap();
        (0..len)
            .map(|_| random_field::<G>(bits, rng))
            .collect::<Vec<G::ScalarField>>()
    };

    let cs = create_test_constraint_system_not_gnrc::<G, EFqSponge, EFrSponge>(inputs.len());

    let witness = not_gnrc_witness::<G>(&inputs, bits);

    // test public input and not generic gate
    for row in 0..2 {
        assert_eq!(
            cs.gates[row].verify_witness::<G>(
                row,
                &witness,
                &cs,
                &witness[0][0..cs.public].to_vec()
            ),
            Ok(())
        );
    }

    check_not_gnrc::<G>(&witness, &inputs, bits);

    witness
}

// Manually checks the NOT of each crumb in the witness
fn check_not_xor<G: KimchiCurve>(
    witness: &[Vec<G::ScalarField>; COLUMNS],
    input: G::ScalarField,
    bits: Option<usize>,
) {
    let input_big = input.to_biguint();
    let bits = max(big_bits(&input_big), bits.unwrap_or(0));
    check_xor::<G>(&witness, bits, input, all_ones::<G>(bits), NOT);
    assert_eq!(
        witness[2][1],
        BigUint::bitnot(&input_big, Some(bits)).into()
    );
}

// Manually checks the NOTs of a vector of inputs in generic gates
fn check_not_gnrc<G: KimchiCurve>(
    witness: &[Vec<G::ScalarField>; COLUMNS],
    inputs: &Vec<G::ScalarField>,
    bits: usize,
) {
    for (i, input) in inputs.iter().enumerate() {
        let input = input.to_biguint();
        if i % 2 == 0 {
            assert_eq!(
                witness[2][1 + i / 2],
                BigUint::bitnot(&input, Some(bits)).into()
            );
        } else {
            assert_eq!(
                witness[5][1 + (i - 1) / 2],
                BigUint::bitnot(&input, Some(bits)).into()
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

    let witness = not_xor_witness::<Vesta>(random_field::<Vesta>(bits, rng), bits);

    TestFramework::<Vesta>::default()
        .gates(gates)
        .witness(witness)
        .public_inputs(vec![
            PallasField::from(2u32).pow(&[bits as u64]) - PallasField::one(),
        ])
        .lookup_tables(vec![xor::lookup_table()])
        .setup()
        .prove_and_verify::<VestaBaseSponge, VestaScalarSponge>();
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
    let witness: [Vec<PallasField>; 15] = not_gnrc_witness::<Vesta>(
        &(0..5)
            .map(|_| random_field::<Vesta>(bits, rng))
            .collect::<Vec<PallasField>>(),
        bits,
    );

    TestFramework::<Vesta>::default()
        .gates(gates)
        .witness(witness)
        .public_inputs(vec![
            PallasField::from(2u32).pow(&[bits as u64]) - PallasField::one(),
        ])
        .setup()
        .prove_and_verify::<VestaBaseSponge, VestaScalarSponge>();
}

#[test]
// Tests all possible 16 values for a crumb, for both full 4, 8, 12, and 16 bits, and smallest
fn test_not_xor_all_crumb() {
    for i in 0..2u8.pow(4) {
        let input = PallasField::from(i);
        test_not_xor::<Vesta, VestaBaseSponge, VestaScalarSponge>(Some(input), None);
        for c in (4..=16).step_by(4) {
            let bits = Some(c);
            test_not_xor::<Vesta, VestaBaseSponge, VestaScalarSponge>(Some(input), bits);
        }
    }
}

#[test]
// Tests NOT for bitlengths of 4, 8, 16, 32, 64, 128, for both exact output width and varying
fn test_not_xor_crumbs_random() {
    for i in 2..=7 {
        let bits = 2u32.pow(i) as usize;
        let rng = &mut StdRng::from_seed(RNG_SEED);
        let input = random_field::<Vesta>(bits, rng);
        test_not_xor::<Vesta, VestaBaseSponge, VestaScalarSponge>(Some(input), Some(bits));
        test_not_xor::<Vesta, VestaBaseSponge, VestaScalarSponge>(Some(input), None);
    }
}

#[test]
// Tests a NOT for a random-length big input
fn test_not_xor_big_random() {
    let rng = &mut StdRng::from_seed(RNG_SEED);
    let input = random_field::<Vesta>(200, rng);
    test_not_xor::<Vesta, VestaBaseSponge, VestaScalarSponge>(Some(input), None);
    let input = random_field::<Pallas>(200, rng);
    test_not_xor::<Pallas, PallasBaseSponge, PallasScalarSponge>(Some(input), None);
}

#[test]
// Tests two NOTs with the generic builder
fn test_not_gnrc_double() {
    test_not_gnrc::<Vesta, VestaBaseSponge, VestaScalarSponge>(None, 64, Some(2));
    test_not_gnrc::<Pallas, PallasBaseSponge, PallasScalarSponge>(None, 64, Some(2));
}

#[test]
// Tests one NOT with the generic builder
fn test_not_gnrc_single() {
    test_not_gnrc::<Vesta, VestaBaseSponge, VestaScalarSponge>(None, 64, Some(1));
    test_not_gnrc::<Pallas, PallasBaseSponge, PallasScalarSponge>(None, 64, Some(1));
}

#[test]
// Tests a chain of 5 NOTs with different lengths but padded to 254 bits with the generic builder
fn test_not_gnrc_vector() {
    let rng = &mut StdRng::from_seed(RNG_SEED);
    // up to 2^16, 2^32, 2^64, 2^128, 2^254
    let inputs = (0..5)
        .map(|i| random_field::<Vesta>(4 + i, rng))
        .collect::<Vec<PallasField>>();
    test_not_gnrc::<Vesta, VestaBaseSponge, VestaScalarSponge>(Some(inputs), 254, None);
    let inputs = (0..5)
        .map(|i| random_field::<Pallas>(4 + i, rng))
        .collect::<Vec<VestaField>>();
    test_not_gnrc::<Pallas, PallasBaseSponge, PallasScalarSponge>(Some(inputs), 254, None);
}
