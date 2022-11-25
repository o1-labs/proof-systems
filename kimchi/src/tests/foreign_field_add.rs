use super::framework::TestFramework;
use crate::circuits::{
    constraints::ConstraintSystem,
    gate::{CircuitGate, CircuitGateError, GateType},
    polynomial::COLUMNS,
    polynomials::foreign_field_add::{
        self,
        witness::{self, FFOps},
    },
    wires::Wire,
};
use ark_ec::AffineCurve;
use ark_ff::{One, Zero};
use mina_curves::pasta::{Fp, Pallas, Vesta, VestaParameters};
use mina_poseidon::{
    constants::PlonkSpongeConstantsKimchi,
    sponge::{DefaultFqSponge, DefaultFrSponge},
};
use num_bigint::BigUint;
use num_traits::FromPrimitive;
use o1_utils::{
    foreign_field::{ForeignElement, HI, LO, MI, TWO_TO_LIMB},
    FieldHelpers,
};
use rand::{rngs::StdRng, Rng, SeedableRng};

type PallasField = <Pallas as AffineCurve>::BaseField;
type VestaField = <Vesta as AffineCurve>::BaseField;

type SpongeParams = PlonkSpongeConstantsKimchi;
type BaseSponge = DefaultFqSponge<VestaParameters, SpongeParams>;
type ScalarSponge = DefaultFrSponge<Fp, SpongeParams>;

// The secp256k1 base field modulus
fn secp256k1_modulus() -> BigUint {
    BigUint::from_bytes_be(&secp256k1::constants::FIELD_SIZE)
}

// Maximum value in the foreign field of secp256k1
fn secp256k1_max() -> BigUint {
    secp256k1_modulus() - BigUint::from(1u32)
}

// A value that produces a negative low carry when added to itself
static OVF_NEG_LO: &[u8] = &[
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

// A value that produces a negative middle carry when added to itself
static OVF_NEG_MI: &[u8] = &[
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFC, 0x2E,
];

// A value that produces overflow but the high limb of the result is smaller than the high limb of the modulus
static OVF_LESS_HI_LEFT: &[u8] = &[
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFC, 0x2E,
];
static OVF_LESS_HI_RIGHT: &[u8] = &[
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x03, 0xD1,
];

// A value that produces two negative carries when added together with [OVF_ZERO_MI_NEG_LO]
static OVF_NEG_BOTH: &[u8] = &[
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

// A value that produces two negative carries when added to itself with a middle limb that is all zeros
static OVF_ZERO_MI_NEG_LO: &[u8] = &[
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

// All 0x55 bytes meaning [0101 0101]
static TIC: &[u8] = &[
    0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
    0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
];

// Prefix 0xAA bytes but fits in foreign field (suffix is zeros)
static TOC: &[u8] = &[
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0x00, 0x00, 0x00, 0x00, 0x00,
];

// Bytestring that produces carry in low limb when added to TIC
static TOC_LO: &[u8] = &[
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
    0xAA, 0xAA, 0xAA, 0xAA, 0xA9, 0xBA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0x00, 0x00, 0x00, 0x00, 0x00,
];

// Bytestring that produces carry in mid limb when added to TIC
static TOC_MI: &[u8] = &[
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xA9, 0xBA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0x00, 0x00, 0x00, 0x00, 0x00,
];

// Bytestring that produces carry in low and mid limb when added to TIC
static TOC_TWO: &[u8] = &[
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xA9, 0xBA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
    0xAA, 0xAA, 0xAA, 0xAA, 0xA9, 0xBA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0x00, 0x00, 0x00, 0x00, 0x00,
];

//  Bottom half of the secp256k1 base field modulus
fn secp256k1_modulus_bottom() -> BigUint {
    BigUint::from_bytes_be(&secp256k1::constants::FIELD_SIZE[16..])
}

// Top half of the secp256k1 base field modulus
fn secp256k1_modulus_top() -> BigUint {
    let bytes = [&secp256k1::constants::FIELD_SIZE[0..16], &[0; 16]].concat();
    BigUint::from_bytes_be(&bytes)
}

// Value that performs a + - 1 low carry when added to [MAX]
static NULL_CARRY_LO: &[u8] = &[0x01, 0x00, 0x00, 0x03, 0xD2];

// Value that performs a + - 1 middle carry when added to [MAX]
static NULL_CARRY_MI: &[u8] = &[
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
];

// Value that performs two + - 1 carries when added to [MAX]
static NULL_CARRY_BOTH: &[u8] = &[
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x03, 0xD2,
];

fn create_test_constraint_system_ffadd(
    num: usize,
    modulus: BigUint,
) -> ConstraintSystem<PallasField> {
    let (mut next_row, mut gates) = CircuitGate::<PallasField>::create_foreign_field_add(0, num);

    // Temporary workaround for lookup-table/domain-size issue
    for _ in 0..(1 << 13) {
        gates.push(CircuitGate::zero(Wire::for_row(next_row)));
        next_row += 1;
    }

    ConstraintSystem::create(gates)
        .foreign_field_modulus(&Some(modulus))
        .build()
        .unwrap()
}

// returns the maximum value for a field of modulus size
fn field_max(modulus: BigUint) -> BigUint {
    modulus - 1u32
}

// helper to reduce lines of code in repetitive test structure
fn test_ffadd(
    foreign_modulus: BigUint,
    inputs: Vec<BigUint>,
    ops: &Vec<FFOps>,
) -> ([Vec<PallasField>; COLUMNS], ConstraintSystem<PallasField>) {
    let nops = ops.len();
    let cs = create_test_constraint_system_ffadd(nops, foreign_modulus.clone());
    let witness = witness::create(&inputs, ops, foreign_modulus);

    let all_rows = witness[0].len();

    for row in 0..all_rows {
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

    // the row structure from the end will be: n ffadds, 1 final add, 1 final zero
    let add_row = all_rows - nops - 2;

    for row in add_row..all_rows {
        assert_eq!(
            cs.gates[row].verify::<Vesta>(row, &witness, &cs, &[]),
            Ok(())
        );
    }

    (witness, cs)
}

// checks that the result cells of the witness are computed as expected
fn check_result(witness: [Vec<PallasField>; COLUMNS], result: Vec<ForeignElement<PallasField, 3>>) {
    let add_row = witness[0].len() - 1 - result.len();
    for (idx, res) in result.iter().enumerate() {
        assert_eq!(witness[0][add_row + idx], res[LO]);
        assert_eq!(witness[1][add_row + idx], res[MI]);
        assert_eq!(witness[2][add_row + idx], res[HI]);
    }
}

// checks the result of the overflow bit
fn check_ovf(witness: [Vec<PallasField>; COLUMNS], ovf: PallasField) {
    let ovf_row = witness[0].len() - 3;
    assert_eq!(witness[7][ovf_row], ovf);
}

// checks the result of the carry bits
fn check_carry(witness: [Vec<PallasField>; COLUMNS], lo: PallasField, mi: PallasField) {
    let carry_row = witness[0].len() - 3;
    assert_eq!(witness[8][carry_row], lo);
    assert_eq!(witness[9][carry_row], mi);
}

// computes the result of an addition
fn compute_sum(modulus: BigUint, left: &[u8], right: &[u8]) -> BigUint {
    let left_big = BigUint::from_bytes_be(&left);
    let right_big = BigUint::from_bytes_be(&right);
    (left_big + right_big) % modulus
}

// computes the result of a subtraction
fn compute_dif(modulus: BigUint, left: &[u8], right: &[u8]) -> BigUint {
    let left_big = BigUint::from_bytes_be(&left);
    let right_big = BigUint::from_bytes_be(&right);
    if left_big < right_big {
        left_big + modulus - right_big
    } else {
        left_big - right_big
    }
}

// obtains a random input of 32 bytes that fits in the foreign modulus
fn random_input(modulus: BigUint, big: bool) -> Vec<u8> {
    let mut random_str = vec![];
    let mut random_big = BigUint::from_u128(2u128.pow(88)).unwrap().pow(3);
    while random_big > modulus {
        random_str = if big {
            rand::thread_rng().gen::<[u8; 32]>().to_vec()
        } else {
            rand::thread_rng().gen::<[u8; 20]>().to_vec()
        };
        random_big = BigUint::from_bytes_be(&random_str);
    }
    random_str
}

// obtains a random operation
fn random_operation(rng: &mut StdRng) -> FFOps {
    let op: u32 = rng.gen_range(0..2);
    match op {
        0 => FFOps::Add,
        1 => FFOps::Sub,
        _ => panic!("Invalid operation"),
    }
}

fn prove_and_verify(operation_count: usize) {
    let rng = &mut StdRng::from_seed([
        0, 131, 43, 175, 229, 252, 206, 26, 67, 193, 86, 160, 1, 90, 131, 86, 168, 4, 95, 50, 48,
        9, 192, 13, 250, 215, 172, 130, 24, 164, 162, 221,
    ]);

    // Create circuit
    let (mut next_row, mut gates) =
        CircuitGate::<PallasField>::create_foreign_field_add(0, operation_count);
    // Temporary workaround for lookup-table/domain-size issue
    for _ in 0..(1 << 13) {
        gates.push(CircuitGate::zero(Wire::for_row(next_row)));
        next_row += 1;
    }

    // Create foreign modulus
    let foreign_modulus = secp256k1_modulus();

    // Create inputs and operations
    let inputs = (0..operation_count + 1)
        .into_iter()
        .map(|_| BigUint::from_bytes_be(&random_input(foreign_modulus.clone(), true)))
        .collect::<Vec<BigUint>>();
    let operations = (0..operation_count)
        .into_iter()
        .map(|_| random_operation(rng))
        .collect::<Vec<_>>();

    // Create witness
    let witness = witness::create(&inputs, &operations, foreign_modulus.clone());

    TestFramework::<Vesta>::default()
        .gates(gates)
        .witness(witness)
        .lookup_tables(vec![foreign_field_add::gadget::lookup_table()])
        .foreign_modulus(Some(foreign_modulus))
        .setup()
        .prove_and_verify::<BaseSponge, ScalarSponge>();
}

#[test]
// Add zero to zero. This checks that small amounts also get packed into limbs
fn test_zero_add() {
    test_ffadd(
        secp256k1_modulus(),
        vec![BigUint::zero(), BigUint::zero()],
        &vec![FFOps::Add],
    );
}

#[test]
// Adding terms that are zero modulo the foreign field
fn test_zero_sum_foreign() {
    let (witness, _cs) = test_ffadd(
        secp256k1_modulus(),
        vec![secp256k1_modulus_bottom(), secp256k1_modulus_top()],
        &vec![FFOps::Add],
    );
    check_result(witness, vec![ForeignElement::zero()]);
}

#[test]
// Adding terms that are zero modulo the native field
fn test_zero_sum_native() {
    let native_modulus = PallasField::modulus_biguint();
    let one = BigUint::new(vec![1u32]);
    let mod_minus_one = native_modulus.clone() - one.clone();
    let (witness, _cs) = test_ffadd(
        secp256k1_modulus(),
        vec![One::one(), mod_minus_one],
        &vec![FFOps::Add],
    );

    // Check result is the native modulus
    let native_limbs = ForeignElement::<PallasField, 3>::from_biguint(native_modulus);
    check_result(witness, vec![native_limbs]);
}

#[test]
fn test_one_plus_one() {
    let (witness, _cs) = test_ffadd(
        secp256k1_modulus(),
        vec![One::one(), One::one()],
        &vec![FFOps::Add],
    );
    // check result is 2
    let two = ForeignElement::from_be(&[2]);
    check_result(witness, vec![two]);
}

#[test]
// Adds two terms that are the maximum value in the foreign field
fn test_max_number() {
    let (witness, _cs) = test_ffadd(
        secp256k1_modulus(),
        vec![secp256k1_max(), secp256k1_max()],
        &vec![FFOps::Add],
    );

    // compute result in the foreign field after taking care of the exceeding bits
    let sum = secp256k1_max() + secp256k1_max();
    let sum_mod = sum - secp256k1_modulus();
    let sum_mod_limbs = ForeignElement::<PallasField, 3>::from_biguint(sum_mod);
    check_ovf(witness.clone(), PallasField::one());
    check_result(witness, vec![sum_mod_limbs]);
}

#[test]
// test 0 - 1 where (-1) is in the foreign field
// this is tested first as 0 + neg(1)
// and then as 0 - 1
// and it is checked that in both cases the result is the same
fn test_zero_minus_one() {
    // FIRST AS NEG
    let right_be_neg = ForeignElement::<PallasField, 3>::from_biguint(One::one())
        .neg(&secp256k1_modulus())
        .to_biguint();
    let right_for_neg: ForeignElement<PallasField, 3> =
        ForeignElement::from_biguint(right_be_neg.clone());
    let (witness_neg, _cs) = test_ffadd(
        secp256k1_modulus(),
        vec![BigUint::zero(), right_be_neg],
        &vec![FFOps::Add],
    );
    check_result(witness_neg, vec![right_for_neg.clone()]);

    // NEXT AS SUB
    let (witness_sub, _cs) = test_ffadd(
        secp256k1_modulus(),
        vec![BigUint::zero(), One::one()],
        &vec![FFOps::Sub],
    );
    check_result(witness_sub, vec![right_for_neg]);
}

#[test]
// test 1 - 1 + 1 where (-1) is in the foreign field
// the first check is done with sub(1, 1) and then with add(neg(neg(1)))
fn test_one_minus_one_plus_one() {
    let neg_neg_one = ForeignElement::<PallasField, 3>::from_biguint(One::one())
        .neg(&secp256k1_modulus())
        .neg(&secp256k1_modulus())
        .to_biguint();
    let (witness, _cs) = test_ffadd(
        secp256k1_modulus(),
        vec![One::one(), One::one(), neg_neg_one],
        &vec![FFOps::Sub, FFOps::Add],
    );
    // intermediate 1 - 1 should be zero
    // final 0 + 1 should be 1
    check_result(
        witness,
        vec![
            ForeignElement::zero(),
            ForeignElement::from_biguint(One::one()),
        ],
    );
}

#[test]
// test -1-1 where (-1) is in the foreign field
// first tested as neg(1) + neg(1)
// then tested as 0 - 1 - 1 )
// TODO tested as 0 - ( 1 + 1) -> put sign in front of left instead
fn test_minus_minus() {
    let foreign_modulus = secp256k1_modulus();
    let neg_one_for =
        ForeignElement::<PallasField, 3>::from_biguint(One::one()).neg(&foreign_modulus);
    let neg_one = neg_one_for.to_biguint();
    let neg_two = ForeignElement::<PallasField, 3>::from_biguint(BigUint::from_u32(2).unwrap())
        .neg(&secp256k1_modulus());
    let (witness_neg, _cs) = test_ffadd(
        secp256k1_modulus(),
        vec![neg_one.clone(), neg_one],
        &vec![FFOps::Add],
    );
    check_result(witness_neg, vec![neg_two.clone()]);

    let (witness_sub, _cs) = test_ffadd(
        secp256k1_modulus(),
        vec![BigUint::zero(), One::one(), One::one()],
        &vec![FFOps::Sub, FFOps::Sub],
    );
    check_result(witness_sub, vec![neg_one_for, neg_two]);
}

#[test]
// test when the low carry is minus one
fn test_neg_carry_lo() {
    let (witness, _cs) = test_ffadd(
        secp256k1_modulus(),
        vec![
            BigUint::from_bytes_be(OVF_NEG_LO),
            BigUint::from_bytes_be(OVF_NEG_LO),
        ],
        &vec![FFOps::Add],
    );
    check_carry(witness, -PallasField::one(), PallasField::zero());
}

#[test]
// test when the middle carry is minus one
fn test_neg_carry_mi() {
    let (witness, _cs) = test_ffadd(
        secp256k1_modulus(),
        vec![
            BigUint::from_bytes_be(OVF_NEG_MI),
            BigUint::from_bytes_be(OVF_NEG_MI),
        ],
        &vec![FFOps::Add],
    );
    check_carry(witness, PallasField::zero(), -PallasField::one());
}

#[test]
// test when there is negative low carry and 0 middle limb (carry bit propagates)
fn test_propagate_carry() {
    let (witness, _cs) = test_ffadd(
        secp256k1_modulus(),
        vec![
            BigUint::from_bytes_be(OVF_ZERO_MI_NEG_LO),
            BigUint::from_bytes_be(OVF_ZERO_MI_NEG_LO),
        ],
        &vec![FFOps::Add],
    );
    check_carry(witness, -PallasField::one(), -PallasField::one());
}

#[test]
// test when the both carries are minus one
fn test_neg_carries() {
    let (witness, _cs) = test_ffadd(
        secp256k1_modulus(),
        vec![
            BigUint::from_bytes_be(OVF_NEG_BOTH),
            BigUint::from_bytes_be(OVF_ZERO_MI_NEG_LO),
        ],
        &vec![FFOps::Add],
    );
    check_carry(witness, -PallasField::one(), -PallasField::one());
}

#[test]
// test the upperbound of the result
fn test_upperbound() {
    test_ffadd(
        secp256k1_modulus(),
        vec![
            BigUint::from_bytes_be(OVF_LESS_HI_LEFT),
            BigUint::from_bytes_be(OVF_LESS_HI_RIGHT),
        ],
        &vec![FFOps::Add],
    );
}

#[test]
// test a carry that nullifies in the low limb
fn test_null_lo_carry() {
    let (witness, _cs) = test_ffadd(
        secp256k1_modulus(),
        vec![secp256k1_max(), BigUint::from_bytes_be(NULL_CARRY_LO)],
        &vec![FFOps::Add],
    );
    check_carry(witness, PallasField::zero(), PallasField::zero());
}

#[test]
// test a carry that nullifies in the mid limb
fn test_null_mi_carry() {
    let (witness, _cs) = test_ffadd(
        secp256k1_modulus(),
        vec![secp256k1_max(), BigUint::from_bytes_be(NULL_CARRY_MI)],
        &vec![FFOps::Add],
    );
    check_carry(witness, PallasField::zero(), PallasField::zero());
}

#[test]
// test a carry that nullifies in the mid limb
fn test_null_both_carry() {
    let (witness, _cs) = test_ffadd(
        secp256k1_modulus(),
        vec![secp256k1_max(), BigUint::from_bytes_be(NULL_CARRY_BOTH)],
        &vec![FFOps::Add],
    );
    check_carry(witness, PallasField::zero(), PallasField::zero());
}

#[test]
// test sums without carry bits in any limb
fn test_no_carry_limbs() {
    let (witness, _cs) = test_ffadd(
        secp256k1_modulus(),
        vec![BigUint::from_bytes_be(TIC), BigUint::from_bytes_be(TOC)],
        &vec![FFOps::Add],
    );
    check_carry(witness.clone(), PallasField::zero(), PallasField::zero());
    // check middle limb is all ones
    let all_one_limb = PallasField::from(2u128.pow(88) - 1);
    assert_eq!(witness[1][17], all_one_limb);
}

#[test]
// test sum with carry only in low part
fn test_pos_carry_limb_lo() {
    let (witness, _cs) = test_ffadd(
        secp256k1_modulus(),
        vec![BigUint::from_bytes_be(TIC), BigUint::from_bytes_be(TOC_LO)],
        &vec![FFOps::Add],
    );
    check_carry(witness, PallasField::one(), PallasField::zero());
}

#[test]
fn test_pos_carry_limb_mid() {
    let (witness, _cs) = test_ffadd(
        secp256k1_modulus(),
        vec![BigUint::from_bytes_be(TIC), BigUint::from_bytes_be(TOC_MI)],
        &vec![FFOps::Add],
    );
    check_carry(witness, PallasField::zero(), PallasField::one());
}

#[test]
fn test_pos_carry_limb_lo_mid() {
    let (witness, _cs) = test_ffadd(
        secp256k1_modulus(),
        vec![BigUint::from_bytes_be(TIC), BigUint::from_bytes_be(TOC_TWO)],
        &vec![FFOps::Add],
    );
    check_carry(witness, PallasField::one(), PallasField::one());
}

#[test]
// Check it fails if given a wrong result (sum)
fn test_wrong_sum() {
    let (mut witness, cs) = test_ffadd(
        secp256k1_modulus(),
        vec![BigUint::from_bytes_be(TIC), BigUint::from_bytes_be(TOC)],
        &vec![FFOps::Add],
    );
    // wrong result
    let all_ones_limb = PallasField::from(2u128.pow(88) - 1);
    witness[0][8] = all_ones_limb.clone();
    witness[0][17] = all_ones_limb.clone();

    assert_eq!(
        cs.gates[16].verify_foreign_field_add::<Vesta>(0, &witness, &cs),
        Err(CircuitGateError::InvalidConstraint(
            GateType::ForeignFieldAdd
        )),
    );
}

#[test]
// Check it fails if given a wrong result (difference)
fn test_wrong_dif() {
    let (mut witness, cs) = test_ffadd(
        secp256k1_modulus(),
        vec![BigUint::from_bytes_be(TIC), BigUint::from_bytes_be(TOC)],
        &vec![FFOps::Sub],
    );
    // wrong result
    witness[0][8] = PallasField::zero();
    witness[0][17] = PallasField::zero();

    assert_eq!(
        cs.gates[16].verify_foreign_field_add::<Vesta>(0, &witness, &cs),
        Err(CircuitGateError::InvalidConstraint(
            GateType::ForeignFieldAdd
        )),
    );
}

#[test]
// Test subtraction of the foreign field
fn test_zero_sub_fmod() {
    let (witness, _cs) = test_ffadd(
        secp256k1_modulus(),
        vec![BigUint::zero(), secp256k1_modulus()],
        &vec![FFOps::Sub],
    );
    // -f should be 0 mod f
    check_result(witness, vec![ForeignElement::zero()]);
}

#[test]
// Test subtraction of the foreign field maximum value
fn test_zero_sub_fmax() {
    let (witness, _cs) = test_ffadd(
        secp256k1_modulus(),
        vec![BigUint::zero(), secp256k1_max()],
        &vec![FFOps::Sub],
    );
    let foreign_modulus = secp256k1_modulus();
    let negated =
        ForeignElement::<PallasField, 3>::from_biguint(secp256k1_max()).neg(&foreign_modulus);
    check_result(witness, vec![negated]);
}

// The order of the Pallas curve is 0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000001.
// The order of the Vesta curve is  0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001.

#[test]
// Test with Pasta curves where foreign field is smaller than the native field
fn test_pasta_add_max_vesta() {
    let vesta_modulus = VestaField::modulus_biguint();
    let right_input = field_max(vesta_modulus.clone());
    let (witness, _cs) = test_ffadd(
        vesta_modulus.clone(),
        vec![BigUint::zero(), right_input.clone()],
        &vec![FFOps::Add],
    );
    let right = right_input % vesta_modulus;
    let right_foreign = ForeignElement::<PallasField, 3>::from_biguint(right);
    check_result(witness, vec![right_foreign]);
}

#[test]
// Test with Pasta curves where foreign field is smaller than the native field
fn test_pasta_sub_max_vesta() {
    let vesta_modulus = VestaField::modulus_biguint();
    let right_input = field_max(vesta_modulus.clone());
    let (witness, _cs) = test_ffadd(
        vesta_modulus.clone(),
        vec![BigUint::zero(), right_input.clone()],
        &vec![FFOps::Sub],
    );
    let neg_max_vesta =
        ForeignElement::<PallasField, 3>::from_biguint(right_input).neg(&vesta_modulus);
    check_result(witness, vec![neg_max_vesta]);
}

#[test]
// Test with Pasta curves where foreign field is smaller than the native field
fn test_pasta_add_max_pallas() {
    let vesta_modulus = VestaField::modulus_biguint();
    let right_input = field_max(PallasField::modulus_biguint());
    let (witness, _cs) = test_ffadd(
        vesta_modulus.clone(),
        vec![BigUint::zero(), right_input.clone()],
        &vec![FFOps::Add],
    );
    let right = right_input % vesta_modulus;
    let foreign_right = ForeignElement::<PallasField, 3>::from_biguint(right);
    check_result(witness, vec![foreign_right]);
}

#[test]
// Test with Pasta curves where foreign field is smaller than the native field
fn test_pasta_sub_max_pallas() {
    let vesta_modulus = VestaField::modulus_biguint();
    let right_input = field_max(PallasField::modulus_biguint());
    let (witness, _cs) = test_ffadd(
        vesta_modulus.clone(),
        vec![BigUint::zero(), right_input.clone()],
        &vec![FFOps::Sub],
    );
    let neg_max_pallas =
        ForeignElement::<PallasField, 3>::from_biguint(right_input).neg(&vesta_modulus);
    check_result(witness, vec![neg_max_pallas]);
}

#[test]
// Test with a random addition
fn test_random_add() {
    let foreign_mod = secp256k1_modulus();
    let left_input = random_input(foreign_mod.clone(), true);
    let right_input = random_input(foreign_mod.clone(), true);
    let left_big = BigUint::from_bytes_be(&left_input);
    let right_big = BigUint::from_bytes_be(&right_input);
    let (witness, _cs) = test_ffadd(
        secp256k1_modulus(),
        vec![left_big.clone(), right_big.clone()],
        &vec![FFOps::Add],
    );
    let result =
        ForeignElement::<PallasField, 3>::from_biguint((left_big + right_big) % foreign_mod);
    check_result(witness, vec![result]);
}

#[test]
// Test with a random subtraction
fn test_random_sub() {
    let foreign_mod = secp256k1_modulus();
    let left_input = random_input(foreign_mod.clone(), true);
    let right_input = random_input(foreign_mod.clone(), true);
    let left_big = BigUint::from_bytes_be(&left_input);
    let right_big = BigUint::from_bytes_be(&right_input);
    let (witness, _cs) = test_ffadd(
        secp256k1_modulus(),
        vec![left_big.clone(), right_big.clone()],
        &vec![FFOps::Sub],
    );
    let result = if left_big < right_big {
        ForeignElement::<PallasField, 3>::from_biguint(left_big + foreign_mod - right_big)
    } else {
        ForeignElement::<PallasField, 3>::from_biguint(left_big - right_big)
    };
    check_result(witness, vec![result]);
}

#[test]
// Random test with foreign field being the native field add
fn test_foreign_is_native_add() {
    let pallas = PallasField::modulus_biguint();
    let left_input = random_input(pallas.clone(), true);
    let right_input = random_input(pallas.clone(), true);
    let (witness, _cs) = test_ffadd(
        pallas.clone(),
        vec![
            BigUint::from_bytes_be(&left_input),
            BigUint::from_bytes_be(&right_input),
        ],
        &vec![FFOps::Add],
    );
    // check result was computed correctly
    let sum_big = compute_sum(pallas.clone(), &left_input, &right_input);
    let result = ForeignElement::<PallasField, 3>::from_biguint(sum_big.clone());
    check_result(witness, vec![result.clone()]);
    // check result is in the native field
    let two_to_limb = PallasField::from(TWO_TO_LIMB);
    let left = ForeignElement::<PallasField, 3>::from_be(&left_input);
    let right = ForeignElement::<PallasField, 3>::from_be(&right_input);
    let left = (left[HI] * two_to_limb + left[MI]) * two_to_limb + left[LO];
    let right = (right[HI] * two_to_limb + right[MI]) * two_to_limb + right[LO];
    let sum = left + right;
    let result = (result[HI] * two_to_limb + result[MI]) * two_to_limb + result[LO];
    let sum_from = PallasField::from(sum_big);
    assert_eq!(result, sum);
    assert_eq!(result, sum_from);
}

#[test]
// Random test with foreign field being the native field add
fn test_foreign_is_native_sub() {
    let pallas = PallasField::modulus_biguint();
    let left_input = random_input(pallas.clone(), true);
    let right_input = random_input(pallas.clone(), true);
    let (witness, _cs) = test_ffadd(
        pallas.clone(),
        vec![
            BigUint::from_bytes_be(&left_input),
            BigUint::from_bytes_be(&right_input),
        ],
        &vec![FFOps::Sub],
    );
    // check result was computed correctly
    let dif_big = compute_dif(pallas.clone(), &left_input, &right_input);
    let result = ForeignElement::<PallasField, 3>::from_biguint(dif_big.clone());
    check_result(witness, vec![result.clone()]);
    // check result is in the native field
    let two_to_limb = PallasField::from(TWO_TO_LIMB);
    let left = ForeignElement::<PallasField, 3>::from_be(&left_input);
    let right = ForeignElement::<PallasField, 3>::from_be(&right_input);
    let left = (left[HI] * two_to_limb + left[MI]) * two_to_limb + left[LO];
    let right = (right[HI] * two_to_limb + right[MI]) * two_to_limb + right[LO];
    let dif = left - right;
    let result = (result[HI] * two_to_limb + result[MI]) * two_to_limb + result[LO];
    let dif_from = PallasField::from(dif_big);
    assert_eq!(result, dif);
    assert_eq!(result, dif_from);
}

#[test]
// Test with a random addition
fn test_random_small_add() {
    // 2^200 - 75 is prime with 200 bits (3 limbs but smaller than Pallas)
    let prime = BigUint::from_u128(2u128.pow(100)).unwrap().pow(2) - BigUint::from_u32(75).unwrap();
    let foreign_mod = prime.clone();
    let left_input = random_input(foreign_mod.clone(), false);
    let right_input = random_input(foreign_mod.clone(), false);
    let (witness, _cs) = test_ffadd(
        prime,
        vec![
            BigUint::from_bytes_be(&left_input),
            BigUint::from_bytes_be(&right_input),
        ],
        &vec![FFOps::Add],
    );
    let result = compute_sum(foreign_mod.clone(), &left_input, &right_input);
    check_result(
        witness,
        vec![ForeignElement::<PallasField, 3>::from_biguint(result)],
    );
}

#[test]
// Test with a random subtraction
fn test_random_small_sub() {
    // 2^200 - 75 is prime with 200 bits (3 limbs but smaller than Pallas)
    let prime = BigUint::from_u128(2u128.pow(100)).unwrap().pow(2) - BigUint::from_u32(75).unwrap();
    let foreign_mod = prime.clone();
    let left_input = random_input(foreign_mod.clone(), false);
    let right_input = random_input(foreign_mod.clone(), false);
    let (witness, _cs) = test_ffadd(
        prime,
        vec![
            BigUint::from_bytes_be(&left_input),
            BigUint::from_bytes_be(&right_input),
        ],
        &vec![FFOps::Sub],
    );
    let result = compute_dif(foreign_mod.clone(), &left_input, &right_input);
    check_result(
        witness,
        vec![ForeignElement::<PallasField, 3>::from_biguint(result)],
    );
}

#[test]
// Test with bad left input
fn test_random_bad_input() {
    let foreign_mod = secp256k1_modulus();
    let left_input = random_input(foreign_mod.clone(), false);
    let right_input = random_input(foreign_mod.clone(), false);
    let (mut witness, cs) = test_ffadd(
        secp256k1_modulus(),
        vec![
            BigUint::from_bytes_be(&left_input),
            BigUint::from_bytes_be(&right_input),
        ],
        &vec![FFOps::Sub],
    );
    // First modify left input only to cause an invalid copy constraint
    witness[0][16] = witness[0][16] + PallasField::one();
    assert_eq!(
        cs.gates[16].verify_foreign_field_add::<Vesta>(0, &witness, &cs),
        Err(CircuitGateError::InvalidCopyConstraint(
            GateType::ForeignFieldAdd
        )),
    );
    // then modify the value in the range check to cause an invalid FFAdd constraint
    witness[0][0] = witness[0][0] + PallasField::one();
    assert_eq!(
        cs.gates[16].verify_foreign_field_add::<Vesta>(0, &witness, &cs),
        Err(CircuitGateError::InvalidConstraint(
            GateType::ForeignFieldAdd
        )),
    );
}

#[test]
// Test with bad parameters
fn test_random_bad_parameters() {
    let foreign_mod = secp256k1_modulus();
    let left_input = random_input(foreign_mod.clone(), false);
    let right_input = random_input(foreign_mod.clone(), false);
    let (mut witness, cs) = test_ffadd(
        secp256k1_modulus(),
        vec![
            BigUint::from_bytes_be(&left_input),
            BigUint::from_bytes_be(&right_input),
        ],
        &vec![FFOps::Add],
    );
    // Modify low carry
    witness[8][16] = witness[8][16] + PallasField::one();
    assert_eq!(
        cs.gates[16].verify_foreign_field_add::<Vesta>(0, &witness, &cs),
        Err(CircuitGateError::InvalidConstraint(
            GateType::ForeignFieldAdd
        )),
    );
    witness[8][16] = witness[8][16] - PallasField::one();
    // Modify high carry
    witness[9][16] = witness[9][16] - PallasField::one();
    assert_eq!(
        cs.gates[16].verify_foreign_field_add::<Vesta>(0, &witness, &cs),
        Err(CircuitGateError::InvalidConstraint(
            GateType::ForeignFieldAdd
        )),
    );
    witness[9][16] = witness[9][16] + PallasField::one();
    // Modify overflow
    witness[7][16] = witness[7][16] + PallasField::one();
    assert_eq!(
        cs.gates[16].verify_foreign_field_add::<Vesta>(0, &witness, &cs),
        Err(CircuitGateError::InvalidConstraint(
            GateType::ForeignFieldAdd
        )),
    );
    witness[7][16] = witness[7][16] - PallasField::one();
    // Modify sign
    witness[6][16] = PallasField::zero() - witness[6][16];
    assert_eq!(
        cs.gates[16].verify_foreign_field_add::<Vesta>(0, &witness, &cs),
        Err(CircuitGateError::InvalidConstraint(
            GateType::ForeignFieldAdd
        )),
    );
    witness[6][16] = PallasField::zero() - witness[6][16];
    // Check back to normal
    assert_eq!(
        cs.gates[16].verify_foreign_field_add::<Vesta>(0, &witness, &cs),
        Ok(()),
    );
}

#[test]
// Test with chain of random operations
fn test_random_chain() {
    let rng = &mut StdRng::from_seed([
        0, 131, 43, 175, 229, 252, 206, 26, 67, 193, 86, 160, 1, 90, 131, 86, 168, 4, 95, 50, 48,
        9, 192, 13, 250, 215, 172, 130, 24, 164, 162, 221,
    ]);

    let nops = 20;
    let foreign_mod = secp256k1_modulus();
    let inputs = (0..nops + 1)
        .into_iter()
        .map(|_| random_input(foreign_mod.clone(), true))
        .collect::<Vec<_>>();
    let big_inputs = inputs
        .clone()
        .into_iter()
        .map(|v| BigUint::from_bytes_be(&v))
        .collect::<Vec<_>>();
    let operations = (0..nops)
        .into_iter()
        .map(|_| random_operation(rng))
        .collect::<Vec<_>>();
    let (witness, _cs) = test_ffadd(secp256k1_modulus(), big_inputs, &operations);
    let mut left = vec![inputs[0].clone()];
    let results: Vec<ForeignElement<PallasField, 3>> = operations
        .iter()
        .enumerate()
        .map(|(i, op)| {
            let result = match op {
                FFOps::Add => compute_sum(foreign_mod.clone(), &left[i], &inputs[i + 1]),
                FFOps::Sub => compute_dif(foreign_mod.clone(), &left[i], &inputs[i + 1]),
                _ => panic!("Invalid operation"),
            };
            left.push(result.to_bytes_be());
            ForeignElement::<PallasField, 3>::from_biguint(result)
        })
        .collect();
    check_result(witness, results);
}

// Prove and verify a randomly generated operation
#[test]
fn prove_and_verify_1() {
    prove_and_verify(1);
}

// Prove and verify a chain of 6 randomly generated operations
#[test]
fn prove_and_verify_6() {
    prove_and_verify(6);
}

/*
#[test]
// Test with bad parameters in bound check
// TODO: when the generic is created so it can be linked to a public value
fn test_bad_bound() {
    let foreign_mod = secp256k1_modulus();
    let left_input = random_input(foreign_mod.clone(), false);
    let right_input = random_input(foreign_mod.clone(), false);
    let (mut witness, cs) = test_ffadd(
        secp256k1_modulus(),
        vec![&left_input.clone(), &right_input.clone()],
        &vec![FFOps::Add],
    );
    // Modify sign of bound
    // It should be constrained that sign needs to be 1
    witness[6][17] = -PallasField::one();
    assert_eq!(
        cs.gates[17].verify_foreign_field_add::<Vesta>(0, &witness, &cs),
        Err(CircuitGateError::InvalidCopyConstraint(
            GateType::ForeignFieldAdd
        )),
    );
    witness[6][17] = PallasField::one();
    // Modify overflow
        witness[7][17] = -PallasField::one();
    assert_eq!(
        cs.gates[17].verify_foreign_field_add::<Vesta>(0, &witness, &cs),
        Err(CircuitGateError::InvalidCopyConstraint(
            GateType::ForeignFieldAdd
        )),
    );
    witness[7][17] = PallasField::one();
}*/
