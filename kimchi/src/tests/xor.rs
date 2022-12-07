use std::cmp::max;

use crate::{
    circuits::{
        constraints::ConstraintSystem,
        gate::{CircuitGate, CircuitGateError, GateType},
        polynomial::COLUMNS,
        polynomials::xor::{self},
        wires::Wire,
    },
    curve::KimchiCurve,
    plonk_sponge::FrSponge,
    prover_index::testing::new_index_for_test_with_lookups,
};

use ark_ec::AffineCurve;
use ark_ff::{Field, One, PrimeField, Zero};
use mina_curves::pasta::{Fp, Fq, Pallas, PallasParameters, Vesta, VestaParameters};
use mina_poseidon::{
    constants::PlonkSpongeConstantsKimchi,
    sponge::{DefaultFqSponge, DefaultFrSponge},
    FqSponge,
};
use num_bigint::BigUint;
use o1_utils::{BigUintHelpers, BitOps, FieldHelpers, RandomField};
use rand::{rngs::StdRng, SeedableRng};

use super::framework::TestFramework;

type PallasField = <Pallas as AffineCurve>::BaseField;
type SpongeParams = PlonkSpongeConstantsKimchi;
type VestaBaseSponge = DefaultFqSponge<VestaParameters, SpongeParams>;
type VestaScalarSponge = DefaultFrSponge<Fp, SpongeParams>;
type PallasBaseSponge = DefaultFqSponge<PallasParameters, SpongeParams>;
type PallasScalarSponge = DefaultFrSponge<Fq, SpongeParams>;

const XOR: bool = true;

const RNG_SEED: [u8; 32] = [
    211, 31, 143, 75, 29, 255, 0, 126, 237, 193, 86, 160, 1, 90, 131, 221, 186, 168, 4, 95, 50, 48,
    89, 29, 13, 250, 215, 172, 130, 24, 164, 162,
];

fn create_test_constraint_system_xor<G: KimchiCurve, EFqSponge, EFrSponge>(
    bits: usize,
) -> ConstraintSystem<G::ScalarField>
where
    G::BaseField: PrimeField,
{
    let (mut next_row, mut gates) = CircuitGate::<G::ScalarField>::create_xor_gadget(0, bits);

    // Temporary workaround for lookup-table/domain-size issue
    for _ in 0..(1 << 13) {
        gates.push(CircuitGate::zero(Wire::for_row(next_row)));
        next_row += 1;
    }

    ConstraintSystem::create(gates).build().unwrap()
}

// Returns the all ones BigUint of bits length
pub(crate) fn all_ones<G: KimchiCurve>(bits: usize) -> G::ScalarField {
    G::ScalarField::from(2u128).pow(&[bits as u64]) - G::ScalarField::one()
}

// Returns a given nybble of 4 bits
pub(crate) fn xor_nybble(word: BigUint, nybble: usize) -> BigUint {
    (word >> (4 * nybble)) % 2u128.pow(4)
}

// Manually checks the XOR of each nybble in the witness
pub(crate) fn check_xor<G: KimchiCurve>(
    witness: &[Vec<G::ScalarField>; COLUMNS],
    bits: usize,
    input1: G::ScalarField,
    input2: G::ScalarField,
    not: bool,
) {
    let input1 = input1.to_biguint();
    let input2 = input2.to_biguint();
    let ini_row = if not == XOR { 0 } else { 1 };
    for xor in 0..xor::num_xors(bits) {
        let in1 = (0..4)
            .map(|i| xor_nybble(input1.clone(), i + 4 * xor))
            .collect::<Vec<BigUint>>();
        let in2 = (0..4)
            .map(|i| xor_nybble(input2.clone(), i + 4 * xor))
            .collect::<Vec<BigUint>>();
        for nybble in 0..4 {
            assert_eq!(
                witness[11 + nybble][xor + ini_row],
                BigUint::bitxor(&in1[nybble], &in2[nybble]).into()
            );
        }
    }
    assert_eq!(
        witness[2][ini_row],
        BigUint::bitxor(&input1, &input2).into()
    );
}

// Creates the constraint system and witness for xor, and checks the witness values without
// calling the constraints verification
fn setup_xor<G: KimchiCurve, EFqSponge, EFrSponge>(
    in1: Option<G::ScalarField>,
    in2: Option<G::ScalarField>,
    bits: Option<usize>,
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
    // Initalize inputs
    // If some input was given then use that one, otherwise generate a random one with the given bits
    let input1 = rng.gen(in1, bits);
    let input2 = rng.gen(in2, bits);

    // If user specified a concrete number of bits, use that (if they are sufficient to hold both inputs)
    // Otherwise, use the max number of bits required to hold both inputs (if only one, the other is zero)
    let bits1 = input1.to_biguint().bitlen();
    let bits2 = input2.to_biguint().bitlen();
    let bits = bits.map_or(0, |b| b); // 0 or bits
    let bits = max(bits, max(bits1, bits2));

    let cs = create_test_constraint_system_xor::<G, EFqSponge, EFrSponge>(bits);
    let witness = xor::create_xor_witness(input1, input2, bits);

    check_xor::<G>(&witness, bits, input1, input2, XOR);

    (cs, witness)
}

// General test for Xor, first sets up the xor, and then uses the verification of the constraints
fn test_xor<G: KimchiCurve, EFqSponge, EFrSponge>(
    in1: Option<G::ScalarField>,
    in2: Option<G::ScalarField>,
    bits: Option<usize>,
) -> [Vec<G::ScalarField>; COLUMNS]
where
    G::BaseField: PrimeField,
    EFqSponge: Clone + FqSponge<G::BaseField, G, G::ScalarField>,
    EFrSponge: FrSponge<G::ScalarField>,
{
    let (cs, witness) = setup_xor::<G, EFqSponge, EFrSponge>(in1, in2, bits);
    for row in 0..witness[0].len() {
        assert_eq!(
            cs.gates[row].verify_witness::<G>(row, &witness, &cs, &witness[0][0..cs.public]),
            Ok(())
        );
    }
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

    let input1 = rng.gen_field_with_bits(bits);
    let input2 = rng.gen_field_with_bits(bits);

    // Create witness and random inputs
    let witness = xor::create_xor_witness(input1, input2, bits);

    TestFramework::<Vesta>::default()
        .gates(gates)
        .witness(witness)
        .lookup_tables(vec![xor::lookup_table()])
        .setup()
        .prove_and_verify::<VestaBaseSponge, VestaScalarSponge>();
}

#[test]
// Test a XOR of 64bit whose output is all ones with alternating inputs
fn test_xor64_alternating() {
    let input1 = PallasField::from(6510615555426900570u64);
    let input2 = PallasField::from(11936128518282651045u64);
    let witness =
        test_xor::<Vesta, VestaBaseSponge, VestaScalarSponge>(Some(input1), Some(input2), Some(64));
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
    let zero = PallasField::from_biguint(BigUint::from(0u32)).unwrap();
    let witness =
        test_xor::<Vesta, VestaBaseSponge, VestaScalarSponge>(Some(zero), Some(zero), Some(64));
    assert_eq!(witness[2][0], PallasField::from(0));
}

#[test]
// Test a XOR of 64bit whose inputs are all zero and all one. Checks it works fine with non-dense values.
fn test_xor64_zero_one() {
    let zero = PallasField::from_biguint(BigUint::from(0u32)).unwrap();
    let all_ones = all_ones::<Vesta>(64);
    let witness =
        test_xor::<Vesta, VestaBaseSponge, VestaScalarSponge>(Some(zero), Some(all_ones), None);
    assert_eq!(witness[2][0], all_ones);
}

#[test]
// Tests a XOR of 8 bits for a random input
fn test_xor8_random() {
    test_xor::<Vesta, VestaBaseSponge, VestaScalarSponge>(None, None, Some(8));
    test_xor::<Pallas, PallasBaseSponge, PallasScalarSponge>(None, None, Some(8));
}

#[test]
// Tests a XOR of 16 bits for a random input
fn test_xor16_random() {
    test_xor::<Vesta, VestaBaseSponge, VestaScalarSponge>(None, None, Some(16));
    test_xor::<Pallas, PallasBaseSponge, PallasScalarSponge>(None, None, Some(16));
}

#[test]
// Tests a XOR of 32 bits for a random input
fn test_xor32_random() {
    test_xor::<Vesta, VestaBaseSponge, VestaScalarSponge>(None, None, Some(32));
    test_xor::<Pallas, PallasBaseSponge, PallasScalarSponge>(None, None, Some(32));
}

#[test]
// Tests a XOR of 64 bits for a random input
fn test_xor64_random() {
    test_xor::<Vesta, VestaBaseSponge, VestaScalarSponge>(None, None, Some(64));
    test_xor::<Pallas, PallasBaseSponge, PallasScalarSponge>(None, None, Some(64));
}

#[test]
// Test a random XOR of 128 bits
fn test_xor128_random() {
    test_xor::<Vesta, VestaBaseSponge, VestaScalarSponge>(None, None, Some(128));
    test_xor::<Pallas, PallasBaseSponge, PallasScalarSponge>(None, None, Some(128));
}

fn verify_bad_xor_decomposition<G: KimchiCurve, EFqSponge, EFrSponge>(
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
        witness[col][0] += G::ScalarField::one();
        assert_eq!(
            cs.gates[0].verify_witness::<G>(0, &witness, &cs, &witness[0][0..cs.public]),
            Err(CircuitGateError::Constraint(GateType::Xor16, bad))
        );
        witness[col][0] -= G::ScalarField::one();
    }
    // undo changes
    assert_eq!(
        cs.gates[0].verify_witness::<G>(0, &witness, &cs, &witness[0][0..cs.public]),
        Ok(())
    );
}

#[test]
// Test that a random XOR of 16 bits fails if the inputs do not decompose correctly
fn test_bad_xor_decompsition() {
    let (cs, mut witness) =
        setup_xor::<Vesta, VestaBaseSponge, VestaScalarSponge>(None, None, Some(16));
    verify_bad_xor_decomposition::<Vesta, VestaBaseSponge, VestaScalarSponge>(&mut witness, cs);
}

#[test]
// Test that a 16-bit XOR gate fails if the witness does not correspond to a XOR operation
fn test_bad_xor() {
    let (cs, mut witness) =
        setup_xor::<Vesta, VestaBaseSponge, VestaScalarSponge>(None, None, Some(16));
    // modify the output to be all zero
    witness[2][0] = PallasField::zero();
    for i in 1..=4 {
        witness[COLUMNS - i][0] = PallasField::zero();
    }
    let index =
        new_index_for_test_with_lookups(cs.gates, 0, 0, vec![xor::lookup_table()], None, None);
    assert_eq!(
        index.cs.gates[0].verify_xor::<Vesta>(0, &witness, &index),
        Err(CircuitGateError::InvalidLookupConstraintSorted(
            GateType::Xor16
        ))
    );
}
