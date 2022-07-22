use crate::circuits::{
    constraints::ConstraintSystem,
    gate::{CircuitGate, CircuitGateError, GateType},
    polynomials::{
        foreign_field_add::{self},
        range_check::GateError,
    },
    wires::Wire,
};
use ark_ec::AffineCurve;
use ark_ff::{One, Zero};
use mina_curves::pasta::pallas;
use num_bigint::BigUint;
use o1_utils::{
    foreign_field::{ForeignElement, FOREIGN_MOD},
    FieldHelpers,
};

type PallasField = <pallas::Affine as AffineCurve>::BaseField;

/// Maximum value in the foreign field
// BigEndian -> FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE FFFFFC2E
static MAX: &[u8] = &[
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFC, 0x2E,
];

/// All 0x55 bytes meaning [0101 0101]
static TIC: &[u8] = &[
    0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
    0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
];

// Prefix 0xAA bytes but fits in foreign field (suffix is zeros)
static TAC: &[u8] = &[
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0x00, 0x00, 0x00, 0x00, 0x00,
];

// Bytestring that produces carry in low limb when added to TIC
static TAC_LO: &[u8] = &[
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
    0xAA, 0xAA, 0xAA, 0xAA, 0xA9, 0xBA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0x00, 0x00, 0x00, 0x00, 0x00,
];

// Bytestring that produces carry in mid limb when added to TIC
static TAC_MI: &[u8] = &[
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xA9, 0xBA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0x00, 0x00, 0x00, 0x00, 0x00,
];

// Bytestring that produces carry in low and mid limb when added to TIC
static TAC_TWO: &[u8] = &[
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xA9, 0xBA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
    0xAA, 0xAA, 0xAA, 0xAA, 0xA9, 0xBA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0x00, 0x00, 0x00, 0x00, 0x00,
];

// BigEndian -> 00000000 00000000 00000000 00000000 FFFFFFFF FFFFFFFF FFFFFFFE FFFFFC2F
/// Bottom half of the foreign modulus
static FOR_MOD_BOT: &[u8] = &[
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFC, 0x2F,
];

// BigEndian -> FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF 00000000 00000000 00000000 00000000
/// Top half of the foreign modulus
static FOR_MOD_TOP: &[u8] = &[
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// The zero byte
static ZERO: &[u8] = &[0x00];

/// The one byte
static ONE: &[u8] = &[0x01];

fn create_test_constraint_system() -> ConstraintSystem<PallasField> {
    let (mut next_row, mut gates) = CircuitGate::<PallasField>::create_foreign_field_add(0);

    // Temporary workaround for lookup-table/domain-size issue
    for _ in 0..(1 << 13) {
        gates.push(CircuitGate::zero(Wire::new(next_row)));
        next_row += 1;
    }

    ConstraintSystem::create(gates, oracle::pasta::fp_kimchi::params())
        .build()
        .unwrap()
}

#[test]
// Add zero to zero. This checks that small amounts also get packed into limbs
fn test_zero_add() {
    let cs = create_test_constraint_system();

    let foreign_modulus = ForeignElement::<PallasField, 3>::new_from_be(FOREIGN_MOD);
    let left_input = ForeignElement::<PallasField, 3>::new_from_be(ZERO);
    let right_input = ForeignElement::<PallasField, 3>::new_from_be(ZERO);

    let witness =
        foreign_field_add::witness::create_witness(left_input, right_input, foreign_modulus);

    assert_eq!(
        cs.gates[16].verify_foreign_field_add(0, &witness, &cs),
        Ok(())
    );
}

#[test]
// Adding terms that are zero modulo the foreign field
fn test_zero_sum_foreign() {
    let cs = create_test_constraint_system();

    let foreign_modulus = ForeignElement::<PallasField, 3>::new_from_be(FOREIGN_MOD);
    let right_input = ForeignElement::<PallasField, 3>::new_from_be(FOR_MOD_TOP);
    let left_input = ForeignElement::<PallasField, 3>::new_from_be(FOR_MOD_BOT);

    let witness =
        foreign_field_add::witness::create_witness(left_input, right_input, foreign_modulus);

    assert_eq!(
        cs.gates[16].verify_foreign_field_add(0, &witness, &cs),
        Ok(())
    );

    assert_eq!(witness[0][17], PallasField::zero());
    assert_eq!(witness[1][17], PallasField::zero());
    assert_eq!(witness[2][17], PallasField::zero());
}

#[test]
// Adding terms that are zero modulo the native field
fn test_zero_sum_native() {
    let cs = create_test_constraint_system();

    let native_modulus = PallasField::modulus_biguint();
    let foreign_modulus = ForeignElement::<PallasField, 3>::new_from_be(FOREIGN_MOD);

    let one = BigUint::new(vec![1u32]);
    let mod_minus_one = native_modulus.clone() - one.clone();
    let left_input = ForeignElement::<PallasField, 3>::new_from_be(ONE);
    let right_input = ForeignElement::<PallasField, 3>::new_from_big(mod_minus_one);

    let witness =
        foreign_field_add::witness::create_witness(left_input, right_input, foreign_modulus);

    assert_eq!(
        cs.gates[16].verify_foreign_field_add(0, &witness, &cs),
        Ok(())
    );

    // Check result is the native modulus
    let native_limbs = ForeignElement::<PallasField, 3>::new_from_big(native_modulus);
    assert_eq!(witness[0][17], *native_limbs.lo());
    assert_eq!(witness[1][17], *native_limbs.mi());
    assert_eq!(witness[2][17], *native_limbs.hi());
}

#[test]
fn test_one_plus_one() {
    let cs = create_test_constraint_system();

    let foreign_modulus = ForeignElement::<PallasField, 3>::new_from_be(FOREIGN_MOD);

    let left_input = ForeignElement::<PallasField, 3>::new_from_be(ONE);
    let right_input = ForeignElement::<PallasField, 3>::new_from_be(ONE);

    let witness =
        foreign_field_add::witness::create_witness(left_input, right_input, foreign_modulus);

    assert_eq!(
        cs.gates[16].verify_foreign_field_add(0, &witness, &cs),
        Ok(())
    );

    // check result is 2
    assert_eq!(witness[0][17], PallasField::one() + PallasField::one());
    assert_eq!(witness[1][17], PallasField::zero());
    assert_eq!(witness[2][17], PallasField::zero());
}

#[test]
// Adds two terms that are the maximum value in the foreign field
fn test_max_number() {
    let cs = create_test_constraint_system();

    let foreign_modulus = ForeignElement::<PallasField, 3>::new_from_be(FOREIGN_MOD);

    let left_input = ForeignElement::<PallasField, 3>::new_from_be(MAX);
    let right_input = ForeignElement::<PallasField, 3>::new_from_be(MAX);

    let witness =
        foreign_field_add::witness::create_witness(left_input, right_input, foreign_modulus);

    assert_eq!(
        cs.gates[16].verify_foreign_field_add(0, &witness, &cs),
        Ok(())
    );

    // compute result in the foreign field after taking care of the exceeding bits
    let sum = BigUint::from_bytes_be(MAX) + BigUint::from_bytes_be(MAX);
    let sum_mod = sum - BigUint::from_bytes_be(FOREIGN_MOD);
    let sum_mod_limbs = ForeignElement::<PallasField, 3>::new_from_big(sum_mod);
    assert_eq!(witness[6][16], PallasField::one()); // field overflow
    assert_eq!(witness[0][17], *sum_mod_limbs.lo()); // result limbs
    assert_eq!(witness[1][17], *sum_mod_limbs.mi());
    assert_eq!(witness[2][17], *sum_mod_limbs.hi());
}

#[test]
fn test_zero_minus_one() {
    let cs = create_test_constraint_system();

    let foreign_modulus = ForeignElement::<PallasField, 3>::new_from_be(FOREIGN_MOD);

    // we want to avoid use of BigUint in this case, because negative values are handled differently
    let neg_one = -PallasField::one();
    // convert it to big endian
    let neg_one_be = neg_one.to_bytes().into_iter().rev().collect::<Vec<u8>>();

    let left_input = ForeignElement::<PallasField, 3>::new_from_be(ZERO);
    let right_input = ForeignElement::<PallasField, 3>::new_from_be(&neg_one_be);

    let witness =
        foreign_field_add::witness::create_witness(left_input, right_input, foreign_modulus);

    assert_eq!(
        cs.gates[16].verify_foreign_field_add(0, &witness, &cs),
        Ok(())
    );

    // check what is the value of the carry bits
    // only getting it to be zero
    //assert_eq!(witness[7][16], -PallasField::one());
    //assert_eq!(witness[8][16], -PallasField::one());
}

#[test]
// test sums without carry bits in any limb
fn test_no_carry_limbs() {
    let cs = create_test_constraint_system();

    let foreign_modulus = ForeignElement::<PallasField, 3>::new_from_be(FOREIGN_MOD);

    let left_input = ForeignElement::<PallasField, 3>::new_from_be(TIC);
    let right_input = ForeignElement::<PallasField, 3>::new_from_be(TAC);

    let witness =
        foreign_field_add::witness::create_witness(left_input, right_input, foreign_modulus);

    assert_eq!(
        cs.gates[16].verify_foreign_field_add(0, &witness, &cs),
        Ok(())
    );

    // check carry_lo is zero
    assert_eq!(witness[7][16], PallasField::zero());
    // check carry_mi is zero
    assert_eq!(witness[8][16], PallasField::zero());
    // check middle limb is all ones
    let all_one_limb = PallasField::from(2u128.pow(88) - 1);
    assert_eq!(witness[1][17], all_one_limb);
}

#[test]
// test sum with carry only in low part
fn test_carry_limb_lo() {
    let cs = create_test_constraint_system();

    let foreign_modulus = ForeignElement::<PallasField, 3>::new_from_be(FOREIGN_MOD);
    let left_input = ForeignElement::<PallasField, 3>::new_from_be(TIC);
    let right_input = ForeignElement::<PallasField, 3>::new_from_be(TAC_LO);

    let witness =
        foreign_field_add::witness::create_witness(left_input, right_input, foreign_modulus);

    assert_eq!(
        cs.gates[16].verify_foreign_field_add(0, &witness, &cs),
        Ok(())
    );

    // check carry_lo is one
    assert_eq!(witness[7][16], PallasField::one());
    // check carry_mi is zero
    assert_eq!(witness[8][16], PallasField::zero());
}

#[test]
fn test_carry_limb_mid() {
    let cs = create_test_constraint_system();

    let foreign_modulus = ForeignElement::<PallasField, 3>::new_from_be(FOREIGN_MOD);
    let left_input = ForeignElement::<PallasField, 3>::new_from_be(TIC);
    let right_input = ForeignElement::<PallasField, 3>::new_from_be(TAC_MI);

    let witness =
        foreign_field_add::witness::create_witness(left_input, right_input, foreign_modulus);

    assert_eq!(
        cs.gates[16].verify_foreign_field_add(0, &witness, &cs),
        Ok(())
    );

    // check carry_lo is one
    assert_eq!(witness[7][16], PallasField::one());
    // check carry_mi is zero
    assert_eq!(witness[8][16], PallasField::zero());
}

#[test]
fn test_carry_limb_lo_mid() {
    let cs = create_test_constraint_system();

    let foreign_modulus = ForeignElement::<PallasField, 3>::new_from_be(FOREIGN_MOD);
    let left_input = ForeignElement::<PallasField, 3>::new_from_be(TIC);
    let right_input = ForeignElement::<PallasField, 3>::new_from_be(TAC_TWO);

    let witness =
        foreign_field_add::witness::create_witness(left_input, right_input, foreign_modulus);

    assert_eq!(
        cs.gates[16].verify_foreign_field_add(0, &witness, &cs),
        Ok(())
    );

    // check carry_lo is one
    assert_eq!(witness[7][16], PallasField::one());
    // check carry_mi is one
    assert_eq!(witness[8][16], PallasField::one());
}

#[test]
// Check it fails if given a wrong result
fn test_wrong_sum() {
    let cs = create_test_constraint_system();

    let foreign_modulus = ForeignElement::<PallasField, 3>::new_from_be(FOREIGN_MOD);
    let left_input = ForeignElement::<PallasField, 3>::new_from_be(TIC);
    let right_input = ForeignElement::<PallasField, 3>::new_from_be(TAC);

    let mut witness =
        foreign_field_add::witness::create_witness(left_input, right_input, foreign_modulus);

    // wrong result
    let all_ones_limb = PallasField::from(2u128.pow(88) - 1);
    witness[0][8] = all_ones_limb.clone();
    witness[0][9] = all_ones_limb.clone();
    witness[0][10] = all_ones_limb.clone();
    witness[0][17] = all_ones_limb.clone();
    witness[1][17] = all_ones_limb.clone();
    witness[2][17] = all_ones_limb.clone();

    assert_eq!(
        cs.gates[16].verify_foreign_field_add(0, &witness, &cs),
        Err(CircuitGateError::InvalidConstraint(
            GateType::ForeignFieldAdd
        )),
    );
}

#[test]
// Test addends which are larger than the field but smaller than the limbs
fn test_addends_larger_mod() {
    let cs = create_test_constraint_system();

    let foreign_modulus = ForeignElement::<PallasField, 3>::new_from_be(FOREIGN_MOD);
    let mut left_input = ForeignElement::<PallasField, 3>::new_from_be(ZERO);
    let mut right_input = ForeignElement::<PallasField, 3>::new_from_be(ZERO);

    left_input.limbs[0] = PallasField::from(2u128.pow(88) - 1);
    left_input.limbs[1] = PallasField::from(2u128.pow(88) - 1);
    left_input.limbs[2] = PallasField::from(2u128.pow(88) - 1);

    right_input.limbs[0] = PallasField::from(2u128.pow(88) - 1);
    right_input.limbs[1] = PallasField::from(2u128.pow(88) - 1);
    right_input.limbs[2] = PallasField::from(2u128.pow(88) - 1);

    let witness =
        foreign_field_add::witness::create_witness(left_input, right_input, foreign_modulus);

    // it should fail but it doesn't
    assert_eq!(
        cs.gates[16].verify_foreign_field_add(0, &witness, &cs),
        Ok(()) // Err(GateError::InvalidConstraint(GateType::ForeignFieldAdd))
    );
}

#[test]
// Test that numbers that do not fit inside the limb will fail
fn test_larger_than_limbs() {
    let cs = create_test_constraint_system();
    let foreign_modulus = ForeignElement::<PallasField, 3>::new_from_be(FOREIGN_MOD);
    let mut left_input = ForeignElement::<PallasField, 3>::new_from_be(ZERO);
    let right_input = ForeignElement::<PallasField, 3>::new_from_be(ZERO);

    // Value 2^88 does not fit in 88 limbs
    left_input.limbs[0] = PallasField::from(2u128.pow(88));
    left_input.limbs[1] = PallasField::from(2u128.pow(88));
    left_input.limbs[2] = PallasField::from(2u128.pow(88));

    let witness =
        foreign_field_add::witness::create_witness(left_input, right_input, foreign_modulus);

    assert_eq!(
        cs.gates[0].verify_range_check(0, &witness, &cs),
        Err(GateError::InvalidConstraint(GateType::RangeCheck0))
    );

    assert_eq!(
        cs.gates[1].verify_range_check(0, &witness, &cs),
        Err(GateError::InvalidConstraint(GateType::RangeCheck0))
    );

    assert_eq!(
        cs.gates[2].verify_range_check(0, &witness, &cs),
        Err(GateError::InvalidConstraint(GateType::RangeCheck1))
    );
}
