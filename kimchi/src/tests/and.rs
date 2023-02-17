use crate::{
    circuits::{
        constraints::ConstraintSystem,
        gate::{CircuitGate, CircuitGateError, GateType},
        polynomial::COLUMNS,
        polynomials::{and, xor},
        wires::Wire,
    },
    curve::KimchiCurve,
    plonk_sponge::FrSponge,
};

use ark_ec::AffineCurve;
use ark_ff::{One, PrimeField, Zero};
use mina_curves::pasta::{Fp, Fq, Pallas, PallasParameters, Vesta, VestaParameters};
use mina_poseidon::{
    constants::PlonkSpongeConstantsKimchi,
    sponge::{DefaultFqSponge, DefaultFrSponge},
    FqSponge,
};
use num_bigint::BigUint;
use o1_utils::{BitwiseOps, FieldHelpers, RandomField};
use rand::{rngs::StdRng, SeedableRng};

use super::framework::TestFramework;

type PallasField = <Pallas as AffineCurve>::BaseField;
type VestaField = <Vesta as AffineCurve>::BaseField;
type SpongeParams = PlonkSpongeConstantsKimchi;
type VestaBaseSponge = DefaultFqSponge<VestaParameters, SpongeParams>;
type VestaScalarSponge = DefaultFrSponge<Fp, SpongeParams>;
type PallasBaseSponge = DefaultFqSponge<PallasParameters, SpongeParams>;
type PallasScalarSponge = DefaultFrSponge<Fq, SpongeParams>;

const RNG_SEED: [u8; 32] = [
    255, 27, 111, 55, 22, 200, 10, 1, 0, 136, 56, 16, 2, 30, 31, 77, 18, 11, 40, 53, 5, 8, 189, 92,
    97, 25, 21, 12, 13, 44, 14, 12,
];

fn create_test_gates_and<G: KimchiCurve, EFqSponge, EFrSponge>(
    bytes: usize,
) -> Vec<CircuitGate<G::ScalarField>>
where
    G::BaseField: PrimeField,
    EFqSponge: Clone + FqSponge<G::BaseField, G, G::ScalarField>,
    EFrSponge: FrSponge<G::ScalarField>,
{
    let mut gates = vec![];
    let _next_row = CircuitGate::<G::ScalarField>::extend_and(&mut gates, bytes);

    gates
}

// Manually checks the AND of the witness
fn check_and<G: KimchiCurve>(
    witness: &[Vec<G::ScalarField>; COLUMNS],
    bytes: usize,
    input1: G::ScalarField,
    input2: G::ScalarField,
) {
    let and_row = xor::num_xors(bytes * 8) + 1;
    let big_in1 = input1.to_biguint();
    let big_in2 = input2.to_biguint();
    assert_eq!(witness[3][and_row], input1 + input2);
    assert_eq!(
        witness[4][and_row],
        BigUint::bitwise_xor(&big_in1, &big_in2).into()
    );
    assert_eq!(
        witness[5][and_row],
        BigUint::bitwise_and(&big_in1, &big_in2, bytes).into()
    );
}

fn setup_and<G: KimchiCurve, EFqSponge, EFrSponge>(
    input1: Option<G::ScalarField>,
    input2: Option<G::ScalarField>,
    bytes: usize,
) -> (
    ConstraintSystem<G::ScalarField>,
    [Vec<G::ScalarField>; COLUMNS],
)
where
    G::BaseField: PrimeField,
    EFqSponge: Clone + FqSponge<G::BaseField, G, G::ScalarField>,
    EFrSponge: FrSponge<G::ScalarField>,
{
    let rng = &mut StdRng::from_seed(RNG_SEED);

    let gates = create_test_gates_and::<G, EFqSponge, EFrSponge>(bytes);
    let cs = ConstraintSystem::create(gates).build().unwrap();

    // Initalize inputs
    let input1 = rng.gen(input1, Some(bytes * 8));
    let input2 = rng.gen(input2, Some(bytes * 8));

    let witness = and::create_and_witness(input1, input2, bytes);

    check_and::<G>(&witness, bytes, input1, input2);

    (cs, witness)
}

fn test_and<G: KimchiCurve, EFqSponge, EFrSponge>(
    input1: Option<G::ScalarField>,
    input2: Option<G::ScalarField>,
    bytes: usize,
) -> [Vec<G::ScalarField>; COLUMNS]
where
    G::BaseField: PrimeField,
    EFqSponge: Clone + FqSponge<G::BaseField, G, G::ScalarField>,
    EFrSponge: FrSponge<G::ScalarField>,
{
    let (cs, witness) = setup_and::<G, EFqSponge, EFrSponge>(input1, input2, bytes);

    for row in 0..witness[0].len() {
        assert_eq!(
            cs.gates[row].verify_witness::<G>(row, &witness, &cs, &witness[0][0..cs.public]),
            Ok(())
        );
    }

    witness
}

// Function to create a prover and verifier to test the AND circuit
fn prove_and_verify<G: KimchiCurve, EFqSponge, EFrSponge>(bytes: usize)
where
    G::BaseField: PrimeField,
    EFqSponge: Clone + FqSponge<G::BaseField, G, G::ScalarField>,
    EFrSponge: FrSponge<G::ScalarField>,
{
    let rng = &mut StdRng::from_seed(RNG_SEED);

    // Create
    let mut gates = vec![];
    let _next_row = CircuitGate::<G::ScalarField>::extend_and(&mut gates, bytes);

    // Create inputs
    let input1 = rng.gen(None, Some(bytes * 8));
    let input2 = rng.gen(None, Some(bytes * 8));

    // Create witness
    let witness = and::create_and_witness(input1, input2, bytes);

    assert!(TestFramework::<G>::default()
        .gates(gates)
        .witness(witness)
        .setup()
        .prove_and_verify::<EFqSponge, EFrSponge>()
        .is_ok());
}

#[test]
// End-to-end test
fn test_prove_and_verify() {
    prove_and_verify::<Vesta, VestaBaseSponge, VestaScalarSponge>(8);
    prove_and_verify::<Pallas, PallasBaseSponge, PallasScalarSponge>(8);
}

#[test]
// Test a AND of 64bit whose output is all ones with alternating inputs
fn test_and64_alternating() {
    let input1 = PallasField::from(0x5A5A5A5A5A5A5A5Au64);
    let input2 = PallasField::from(0xA5A5A5A5A5A5A5A5u64);
    test_and::<Vesta, VestaBaseSponge, VestaScalarSponge>(Some(input1), Some(input2), 8);
    let input1 = VestaField::from(0x5A5A5A5A5A5A5A5Au64);
    let input2 = VestaField::from(0xA5A5A5A5A5A5A5A5u64);
    test_and::<Pallas, PallasBaseSponge, PallasScalarSponge>(Some(input1), Some(input2), 8);
}

#[test]
// Test a AND of 64bit whose inputs are zero. Checks it works fine with non-dense values.
fn test_and64_zeros() {
    let zero_pallas = PallasField::from(0u8);
    let zero_vesta = VestaField::from(0u8);
    test_and::<Vesta, VestaBaseSponge, VestaScalarSponge>(Some(zero_pallas), Some(zero_pallas), 8);
    test_and::<Pallas, PallasBaseSponge, PallasScalarSponge>(Some(zero_vesta), Some(zero_vesta), 8);
}

#[test]
// Tests a AND of 8 bits for a random input
fn test_and8_random() {
    test_and::<Vesta, VestaBaseSponge, VestaScalarSponge>(None, None, 1);
    test_and::<Pallas, PallasBaseSponge, PallasScalarSponge>(None, None, 1);
}

#[test]
// Tests a XOR of 16 bits for a random input
fn test_and16_random() {
    test_and::<Vesta, VestaBaseSponge, VestaScalarSponge>(None, None, 2);
    test_and::<Pallas, PallasBaseSponge, PallasScalarSponge>(None, None, 2);
}

#[test]
// Tests a AND of 32 bits for a random input
fn test_and32_random() {
    test_and::<Vesta, VestaBaseSponge, VestaScalarSponge>(None, None, 4);
    test_and::<Pallas, PallasBaseSponge, PallasScalarSponge>(None, None, 4);
}

#[test]
// Tests a AND of 64 bits for a random input
fn test_and64_random() {
    test_and::<Vesta, VestaBaseSponge, VestaScalarSponge>(None, None, 8);
    test_and::<Pallas, PallasBaseSponge, PallasScalarSponge>(None, None, 8);
}

#[test]
// Test a random AND of 128 bits
fn test_and128_random() {
    test_and::<Vesta, VestaBaseSponge, VestaScalarSponge>(None, None, 16);
    test_and::<Pallas, PallasBaseSponge, PallasScalarSponge>(None, None, 16);
}

#[test]
// Test AND when the sum of the inputs overflows the field size
fn test_and_overflow() {
    let bytes = 256 / 8;
    let input_pallas =
        PallasField::from_biguint(&(PallasField::modulus_biguint() - BigUint::one())).unwrap();
    test_and::<Vesta, VestaBaseSponge, VestaScalarSponge>(
        Some(input_pallas),
        Some(input_pallas),
        bytes,
    );
    let input_vesta =
        VestaField::from_biguint(&(VestaField::modulus_biguint() - BigUint::one())).unwrap();
    test_and::<Pallas, PallasBaseSponge, PallasScalarSponge>(
        Some(input_vesta),
        Some(input_vesta),
        bytes,
    );
}

#[test]
// Test AND when the sum of the inputs overflows the field size
fn test_and_overflow_one() {
    let bytes = 256 / 8;
    let input =
        PallasField::from_biguint(&(PallasField::modulus_biguint() - BigUint::one())).unwrap();
    test_and::<Vesta, VestaBaseSponge, VestaScalarSponge>(
        Some(input),
        Some(PallasField::from(1u8)),
        bytes,
    );
    let input =
        VestaField::from_biguint(&(VestaField::modulus_biguint() - BigUint::one())).unwrap();
    test_and::<Pallas, PallasBaseSponge, PallasScalarSponge>(
        Some(input),
        Some(VestaField::from(1u8)),
        bytes,
    );
}

fn verify_bad_and_decomposition<G: KimchiCurve, EFqSponge, EFrSponge>(
    witness: &mut [Vec<G::ScalarField>; COLUMNS],
    cs: ConstraintSystem<G::ScalarField>,
) where
    G::BaseField: PrimeField,
    EFqSponge: Clone + FqSponge<G::BaseField, G, G::ScalarField>,
    EFrSponge: FrSponge<G::ScalarField>,
{
    // modify by one each of the witness cells individually
    for col in 0..COLUMNS {
        // first three columns make fail the ith+1 constraint
        // for the rest, the first 4 make the 1st fail, the following 4 make the 2nd fail, the last 4 make the 3rd fail
        let bad = if col < 3 { col + 1 } else { (col - 3) / 4 + 1 };
        let xor_row = 0;
        let and_row = 2;
        witness[col][xor_row] += G::ScalarField::one();
        // Update copy constraints of generic gate
        if col < 2 {
            assert_eq!(
                cs.gates[0].verify_witness::<G>(0, witness, &cs, &witness[0][0..cs.public]),
                Err(CircuitGateError::CopyConstraint {
                    typ: GateType::Xor16,
                    src: Wire { row: xor_row, col },
                    dst: Wire { row: and_row, col }
                })
            );
            witness[col][and_row] += G::ScalarField::one();
        }
        if col == 2 {
            assert_eq!(
                cs.gates[0].verify_witness::<G>(0, witness, &cs, &witness[0][0..cs.public]),
                Err(CircuitGateError::CopyConstraint {
                    typ: GateType::Xor16,
                    src: Wire { row: xor_row, col },
                    dst: Wire {
                        row: and_row,
                        col: 4
                    },
                })
            );
            witness[4][and_row] += G::ScalarField::one();
        }
        assert_eq!(
            cs.gates[0].verify_witness::<G>(0, witness, &cs, &witness[0][0..cs.public]),
            Err(CircuitGateError::Constraint(GateType::Xor16, bad))
        );
        witness[col][xor_row] -= G::ScalarField::one();
        if col < 2 {
            witness[col][and_row] -= G::ScalarField::one();
        }
        if col == 2 {
            witness[4][and_row] -= G::ScalarField::one();
        }
    }
    // undo changes
    assert_eq!(
        cs.gates[0].verify_witness::<G>(0, witness, &cs, &witness[0][0..cs.public]),
        Ok(())
    );
}

#[test]
// Test AND when the decomposition of the inner XOR is incorrect
fn test_and_bad_decomposition() {
    let (cs, mut witness) = setup_and::<Vesta, VestaBaseSponge, VestaScalarSponge>(None, None, 2);
    verify_bad_and_decomposition::<Vesta, VestaBaseSponge, VestaScalarSponge>(&mut witness, cs);
}

#[test]
// Test AND when the decomposition of the inner XOR is incorrect
fn test_bad_and() {
    let rng = &mut StdRng::from_seed(RNG_SEED);

    let bytes = 2;
    let gates = create_test_gates_and::<Vesta, VestaBaseSponge, VestaScalarSponge>(bytes);

    // Initialize inputs
    let input1 = rng.gen(None, Some(bytes * 8));
    let input2 = rng.gen(None, Some(bytes * 8));

    // Create witness
    let mut witness = and::create_and_witness(input1, input2, bytes);

    // Corrupt the witness: modify the output to be all zero
    witness[2][0] = PallasField::zero();
    for i in 1..=4 {
        witness[COLUMNS - i][0] = PallasField::zero();
    }
    witness[4][2] = PallasField::zero();

    assert_eq!(
        TestFramework::<Vesta>::default()
            .gates(gates)
            .witness(witness)
            .setup()
            .prove_and_verify::<VestaBaseSponge, VestaScalarSponge>(),
        Err(String::from(
            "Custom { row: 2, err: \"generic: incorrect gate\" }"
        ))
    );
}
