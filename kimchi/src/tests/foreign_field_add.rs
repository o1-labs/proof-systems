use crate::circuits::{
    constraints::ConstraintSystem,
    gate::{CircuitGate, CircuitGateError, GateType},
    polynomial::COLUMNS,
    polynomials::foreign_field_add::witness::{create_witness, view_witness},
    wires::Wire,
};
use ark_ec::AffineCurve;
use ark_ff::{One, Zero};
use mina_curves::pasta::{pallas::Pallas, vesta::Vesta};
use num_bigint::BigUint;
use num_traits::FromPrimitive;
use o1_utils::{
    foreign_field::{ForeignElement, FOREIGN_MOD},
    FieldHelpers,
};

type PallasField = <Pallas as AffineCurve>::BaseField;

/// Addition operation
static ADD: bool = true;

/// Subtraction operation
static SUB: bool = false;

/*
/// Maximum number in 3 limbs (2^{264}-1)
static MAX_3_LIMBS: &[u8] = &[
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF,
];
*/

/// Maximum value in the foreign field
// BigEndian -> FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE FFFFFC2E
static MAX: &[u8] = &[
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFC, 0x2E,
];

/// A value that produces a negative low carry when added to itself
static OVF_NEG_LO: &[u8] = &[
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// A value that produces a negative middle carry when added to itself
static OVF_NEG_MI: &[u8] = &[
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFC, 0x2E,
];

/// A value that produces overflow but the high limb of the result is smaller than the high limb of the modulus
static OVF_LESS_HI_LEFT: &[u8] = &[
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFC, 0x2E,
];
static OVF_LESS_HI_RIGHT: &[u8] = &[
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x03, 0xD1,
];

/// A value that produces two negative carries when added together with [OVF_ZERO_MI_NEG_LO]
static OVF_NEG_BOTH: &[u8] = &[
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// A value that produces two negative carries when added to itself with a middle limb that is all zeros
static OVF_ZERO_MI_NEG_LO: &[u8] = &[
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// All 0x55 bytes meaning [0101 0101]
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

/// Value that performs a + - 1 low carry when added to [MAX]
static NULL_CARRY_LO: &[u8] = &[0x01, 0x00, 0x00, 0x03, 0xD2];

/// Value that performs a + - 1 middle carry when added to [MAX]
static NULL_CARRY_MI: &[u8] = &[
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
];

/// Value that performs two + - 1 carries when added to [MAX]
static NULL_CARRY_BOTH: &[u8] = &[
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x03, 0xD2,
];
/// The zero byte
static ZERO: &[u8] = &[0x00];

/// The one byte
static ONE: &[u8] = &[0x01];

fn create_test_constraint_system_one_ffadd() -> ConstraintSystem<PallasField> {
    let (mut next_row, mut gates) = CircuitGate::<PallasField>::create_foreign_field_add(0, 1);

    // Temporary workaround for lookup-table/domain-size issue
    for _ in 0..(1 << 13) {
        gates.push(CircuitGate::zero(Wire::new(next_row)));
        next_row += 1;
    }

    ConstraintSystem::create(gates)
        .foreign_field_modulus(BigUint::from_bytes_be(FOREIGN_MOD))
        .build()
        .unwrap()
}

#[test]
// Add zero to zero. This checks that small amounts also get packed into limbs
fn test_zero_add() {
    let cs = create_test_constraint_system_one_ffadd();

    let foreign_modulus = ForeignElement::<PallasField, 3>::new_from_be(FOREIGN_MOD);
    let left_input = ForeignElement::<PallasField, 3>::new_from_be(ZERO);
    let right_input = ForeignElement::<PallasField, 3>::new_from_be(ZERO);

    let witness = create_witness(vec![left_input, right_input], vec![ADD], foreign_modulus);

    for row in 16..=18 {
        assert_eq!(
            cs.gates[row].verify::<Vesta>(row, &witness, &cs, &[]),
            Ok(())
        );
    }
}

#[test]
// Adding terms that are zero modulo the foreign field
fn test_zero_sum_foreign() {
    let cs = create_test_constraint_system_one_ffadd();

    let foreign_modulus = ForeignElement::<PallasField, 3>::new_from_be(FOREIGN_MOD);
    let left_input = ForeignElement::<PallasField, 3>::new_from_be(FOR_MOD_BOT);
    let right_input = ForeignElement::<PallasField, 3>::new_from_be(FOR_MOD_TOP);

    let witness = create_witness(vec![left_input, right_input], vec![ADD], foreign_modulus);

    for row in 16..=18 {
        assert_eq!(
            cs.gates[row].verify::<Vesta>(row, &witness, &cs, &[]),
            Ok(())
        );
    }

    assert_eq!(witness[0][17], PallasField::zero());
    assert_eq!(witness[1][17], PallasField::zero());
    assert_eq!(witness[2][17], PallasField::zero());
}

#[test]
// Adding terms that are zero modulo the native field
fn test_zero_sum_native() {
    let cs = create_test_constraint_system_one_ffadd();

    let native_modulus = PallasField::modulus_biguint();
    let foreign_modulus = ForeignElement::<PallasField, 3>::new_from_be(FOREIGN_MOD);

    let one = BigUint::new(vec![1u32]);
    let mod_minus_one = native_modulus.clone() - one.clone();
    let left_input = ForeignElement::<PallasField, 3>::new_from_be(ONE);
    let right_input = ForeignElement::<PallasField, 3>::new_from_big(mod_minus_one);

    let witness = create_witness(vec![left_input, right_input], vec![ADD], foreign_modulus);

    for row in 16..=18 {
        assert_eq!(
            cs.gates[row].verify::<Vesta>(row, &witness, &cs, &[]),
            Ok(())
        );
    }

    // Check result is the native modulus
    let native_limbs = ForeignElement::<PallasField, 3>::new_from_big(native_modulus);
    assert_eq!(witness[0][17], *native_limbs.lo());
    assert_eq!(witness[1][17], *native_limbs.mi());
    assert_eq!(witness[2][17], *native_limbs.hi());
}

#[test]
fn test_one_plus_one() {
    let cs = create_test_constraint_system_one_ffadd();

    let foreign_modulus = ForeignElement::<PallasField, 3>::new_from_be(FOREIGN_MOD);

    let left_input = ForeignElement::<PallasField, 3>::new_from_be(ONE);
    let right_input = ForeignElement::<PallasField, 3>::new_from_be(ONE);

    let witness = create_witness(vec![left_input, right_input], vec![ADD], foreign_modulus);

    for row in 16..=18 {
        assert_eq!(
            cs.gates[row].verify::<Vesta>(row, &witness, &cs, &[]),
            Ok(())
        );
    }

    // check result is 2
    assert_eq!(witness[0][17], PallasField::one() + PallasField::one());
    assert_eq!(witness[1][17], PallasField::zero());
    assert_eq!(witness[2][17], PallasField::zero());
}

#[test]
// Adds two terms that are the maximum value in the foreign field
fn test_max_number() {
    let cs = create_test_constraint_system_one_ffadd();

    let foreign_modulus = ForeignElement::<PallasField, 3>::new_from_be(FOREIGN_MOD);

    let left_input = ForeignElement::<PallasField, 3>::new_from_be(MAX);
    let right_input = ForeignElement::<PallasField, 3>::new_from_be(MAX);

    let witness = create_witness(vec![left_input, right_input], vec![ADD], foreign_modulus);

    for row in 16..=18 {
        assert_eq!(
            cs.gates[row].verify::<Vesta>(row, &witness, &cs, &[]),
            Ok(())
        );
    }

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
// test 0 - 1 where (-1) is in the foreign field
fn test_zero_minus_one() {
    let cs = create_test_constraint_system_one_ffadd();

    let foreign_modulus = ForeignElement::<PallasField, 3>::new_from_be(FOREIGN_MOD);

    // big uint of the number 1
    let big_one = BigUint::from_u32(1).unwrap();

    let left_input = ForeignElement::<PallasField, 3>::new_from_be(ZERO);
    let right_input = ForeignElement::<PallasField, 3>::new_from_neg(big_one).unwrap();

    let witness = create_witness(vec![left_input, right_input], vec![ADD], foreign_modulus);

    for row in 16..=18 {
        assert_eq!(
            cs.gates[row].verify::<Vesta>(row, &witness, &cs, &[]),
            Ok(())
        );
    }
    assert_eq!(witness[0][17], *right_input.lo());
    assert_eq!(witness[1][17], *right_input.mi());
    assert_eq!(witness[2][17], *right_input.hi());
}

#[test]
// test 1 - 1 where (-1) is in the foreign field
fn test_one_minus_one() {
    let cs = create_test_constraint_system_one_ffadd();

    let foreign_modulus = ForeignElement::<PallasField, 3>::new_from_be(FOREIGN_MOD);

    // big uint of the number 1
    let big_one = BigUint::from_u32(1).unwrap();

    let left_input = ForeignElement::<PallasField, 3>::new_from_big(big_one.clone());
    let right_input = ForeignElement::<PallasField, 3>::new_from_neg(big_one).unwrap();

    let witness = create_witness(vec![left_input, right_input], vec![ADD], foreign_modulus);

    for row in 16..=18 {
        assert_eq!(
            cs.gates[row].verify::<Vesta>(row, &witness, &cs, &[]),
            Ok(())
        );
    }

    assert_eq!(witness[0][17], PallasField::zero());
    assert_eq!(witness[1][17], PallasField::zero());
    assert_eq!(witness[2][17], PallasField::zero());
}

#[test]
// test -1-1 where (-1) is in the foreign field
fn test_minus_minus() {
    let cs = create_test_constraint_system_one_ffadd();

    let foreign_modulus = ForeignElement::<PallasField, 3>::new_from_be(FOREIGN_MOD);

    // big uint of the number 1
    let big_one = BigUint::from_u32(1).unwrap();
    let big_two = big_one.clone() + big_one.clone();

    let left_input = ForeignElement::<PallasField, 3>::new_from_neg(big_one.clone()).unwrap();
    let right_input = ForeignElement::<PallasField, 3>::new_from_neg(big_one).unwrap();

    let witness = create_witness(vec![left_input, right_input], vec![ADD], foreign_modulus);

    for row in 16..=18 {
        assert_eq!(
            cs.gates[row].verify::<Vesta>(row, &witness, &cs, &[]),
            Ok(())
        );
    }

    let for_neg_two = ForeignElement::<PallasField, 3>::new_from_neg(big_two).unwrap();

    assert_eq!(witness[0][17], *for_neg_two.lo());
    assert_eq!(witness[1][17], *for_neg_two.mi());
    assert_eq!(witness[2][17], *for_neg_two.hi());
}

#[test]
// test when the low carry is minus one
fn test_neg_carry_lo() {
    let cs = create_test_constraint_system_one_ffadd();

    let foreign_modulus = ForeignElement::<PallasField, 3>::new_from_be(FOREIGN_MOD);

    let left_input = ForeignElement::<PallasField, 3>::new_from_be(OVF_NEG_LO);
    let right_input = ForeignElement::<PallasField, 3>::new_from_be(OVF_NEG_LO);

    let witness = create_witness(vec![left_input, right_input], vec![ADD], foreign_modulus);
    view_witness(&witness);
    for row in 16..=18 {
        assert_eq!(
            cs.gates[row].verify::<Vesta>(row, &witness, &cs, &[]),
            Ok(())
        );
    }
    assert_eq!(witness[7][16], -PallasField::one());
    assert_eq!(witness[8][16], PallasField::zero());
}

#[test]
// test when the middle carry is minus one
fn test_neg_carry_mi() {
    let cs = create_test_constraint_system_one_ffadd();

    let foreign_modulus = ForeignElement::<PallasField, 3>::new_from_be(FOREIGN_MOD);

    let left_input = ForeignElement::<PallasField, 3>::new_from_be(OVF_NEG_MI);
    let right_input = ForeignElement::<PallasField, 3>::new_from_be(OVF_NEG_MI);

    let witness = create_witness(vec![left_input, right_input], vec![ADD], foreign_modulus);
    view_witness(&witness);

    for row in 16..=18 {
        assert_eq!(
            cs.gates[row].verify::<Vesta>(row, &witness, &cs, &[]),
            Ok(())
        );
    }
    assert_eq!(witness[7][16], PallasField::zero());
    assert_eq!(witness[8][16], -PallasField::one());
}

#[test]
// test when there is negative low carry and 0 middle limb (carry bit propagates)
fn test_zero_mi() {
    let cs = create_test_constraint_system_one_ffadd();

    let foreign_modulus = ForeignElement::<PallasField, 3>::new_from_be(FOREIGN_MOD);

    let left_input = ForeignElement::<PallasField, 3>::new_from_be(OVF_ZERO_MI_NEG_LO);
    let right_input = ForeignElement::<PallasField, 3>::new_from_be(OVF_ZERO_MI_NEG_LO);

    let witness = create_witness(vec![left_input, right_input], vec![ADD], foreign_modulus);

    for row in 16..=18 {
        assert_eq!(
            cs.gates[row].verify::<Vesta>(row, &witness, &cs, &[]),
            Ok(())
        );
    }
    assert_eq!(witness[7][16], -PallasField::one());
    assert_eq!(witness[8][16], -PallasField::one());
}

#[test]
// test when the both carries are minus one
fn test_neg_carries() {
    let cs = create_test_constraint_system_one_ffadd();

    let foreign_modulus = ForeignElement::<PallasField, 3>::new_from_be(FOREIGN_MOD);

    let left_input = ForeignElement::<PallasField, 3>::new_from_be(OVF_NEG_BOTH);
    let right_input = ForeignElement::<PallasField, 3>::new_from_be(OVF_ZERO_MI_NEG_LO);

    let witness = create_witness(vec![left_input, right_input], vec![ADD], foreign_modulus);

    for row in 0..17 {
        assert_eq!(
            cs.gates[row].verify::<Vesta>(row, &witness, &cs, &[]),
            Ok(())
        );
    }
    assert_eq!(witness[7][16], -PallasField::one());
    assert_eq!(witness[8][16], -PallasField::one());
}

#[test]
// test the upperbound of the result
fn test_upperbound() {
    let cs = create_test_constraint_system_one_ffadd();

    let foreign_modulus = ForeignElement::<PallasField, 3>::new_from_be(FOREIGN_MOD);

    let left_input = ForeignElement::<PallasField, 3>::new_from_be(OVF_LESS_HI_LEFT);
    let right_input = ForeignElement::<PallasField, 3>::new_from_be(OVF_LESS_HI_RIGHT);

    let witness = create_witness(vec![left_input, right_input], vec![ADD], foreign_modulus);

    for row in 16..=17 {
        assert_eq!(
            cs.gates[row].verify::<Vesta>(row, &witness, &cs, &[]),
            Ok(())
        );
    }
}

#[test]
// test a carry that nullifies in the low limb
fn test_null_lo_carry() {
    let cs = create_test_constraint_system_one_ffadd();

    let foreign_modulus = ForeignElement::<PallasField, 3>::new_from_be(FOREIGN_MOD);

    let left_input = ForeignElement::<PallasField, 3>::new_from_be(MAX);
    let right_input = ForeignElement::<PallasField, 3>::new_from_be(NULL_CARRY_LO);

    let witness = create_witness(vec![left_input, right_input], vec![ADD], foreign_modulus);

    for row in 16..17 {
        assert_eq!(
            cs.gates[row].verify::<Vesta>(row, &witness, &cs, &[]),
            Ok(())
        );
    }
    assert_eq!(witness[7][16], PallasField::zero());
}

#[test]
// test a carry that nullifies in the mid limb
fn test_null_mi_carry() {
    let cs = create_test_constraint_system_one_ffadd();

    let foreign_modulus = ForeignElement::<PallasField, 3>::new_from_be(FOREIGN_MOD);

    let left_input = ForeignElement::<PallasField, 3>::new_from_be(MAX);
    let right_input = ForeignElement::<PallasField, 3>::new_from_be(NULL_CARRY_MI);

    let witness = create_witness(vec![left_input, right_input], vec![ADD], foreign_modulus);

    for row in 16..17 {
        assert_eq!(
            cs.gates[row].verify::<Vesta>(row, &witness, &cs, &[]),
            Ok(())
        );
    }
    assert_eq!(witness[8][16], PallasField::zero());
}

#[test]
// test a carry that nullifies in the mid limb
fn test_null_both_carry() {
    let cs = create_test_constraint_system_one_ffadd();

    let foreign_modulus = ForeignElement::<PallasField, 3>::new_from_be(FOREIGN_MOD);

    let left_input = ForeignElement::<PallasField, 3>::new_from_be(MAX);
    let right_input = ForeignElement::<PallasField, 3>::new_from_be(NULL_CARRY_BOTH);

    let witness = create_witness(vec![left_input, right_input], vec![ADD], foreign_modulus);

    for row in 16..17 {
        assert_eq!(
            cs.gates[row].verify::<Vesta>(row, &witness, &cs, &[]),
            Ok(())
        );
    }
    assert_eq!(witness[7][16], PallasField::zero());
    assert_eq!(witness[8][16], PallasField::zero());
}

#[test]
// test sums without carry bits in any limb
fn test_no_carry_limbs() {
    let cs = create_test_constraint_system_one_ffadd();

    let foreign_modulus = ForeignElement::<PallasField, 3>::new_from_be(FOREIGN_MOD);

    let left_input = ForeignElement::<PallasField, 3>::new_from_be(TIC);
    let right_input = ForeignElement::<PallasField, 3>::new_from_be(TOC);

    let witness = create_witness(vec![left_input, right_input], vec![ADD], foreign_modulus);

    for row in 16..17 {
        assert_eq!(
            cs.gates[row].verify::<Vesta>(row, &witness, &cs, &[]),
            Ok(())
        );
    }

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
fn test_pos_carry_limb_lo() {
    let cs = create_test_constraint_system_one_ffadd();

    let foreign_modulus = ForeignElement::<PallasField, 3>::new_from_be(FOREIGN_MOD);
    let left_input = ForeignElement::<PallasField, 3>::new_from_be(TIC);
    let right_input = ForeignElement::<PallasField, 3>::new_from_be(TOC_LO);

    let witness = create_witness(vec![left_input, right_input], vec![ADD], foreign_modulus);

    for row in 16..17 {
        assert_eq!(
            cs.gates[row].verify::<Vesta>(row, &witness, &cs, &[]),
            Ok(())
        );
    }

    // check carry_lo is one
    assert_eq!(witness[7][16], PallasField::one());
    // check carry_mi is zero
    assert_eq!(witness[8][16], PallasField::zero());
}

#[test]
fn test_pos_carry_limb_mid() {
    let cs = create_test_constraint_system_one_ffadd();

    let foreign_modulus = ForeignElement::<PallasField, 3>::new_from_be(FOREIGN_MOD);
    let left_input = ForeignElement::<PallasField, 3>::new_from_be(TIC);
    let right_input = ForeignElement::<PallasField, 3>::new_from_be(TOC_MI);

    let witness = create_witness(vec![left_input, right_input], vec![ADD], foreign_modulus);

    for row in 16..17 {
        assert_eq!(
            cs.gates[row].verify::<Vesta>(row, &witness, &cs, &[]),
            Ok(())
        );
    }

    // check carry_lo is one
    assert_eq!(witness[7][16], PallasField::zero());
    // check carry_mi is zero
    assert_eq!(witness[8][16], PallasField::one());
}

#[test]
fn test_pos_carry_limb_lo_mid() {
    let cs = create_test_constraint_system_one_ffadd();

    let foreign_modulus = ForeignElement::<PallasField, 3>::new_from_be(FOREIGN_MOD);
    let left_input = ForeignElement::<PallasField, 3>::new_from_be(TIC);
    let right_input = ForeignElement::<PallasField, 3>::new_from_be(TOC_TWO);

    let witness = create_witness(vec![left_input, right_input], vec![ADD], foreign_modulus);

    for row in 16..17 {
        assert_eq!(
            cs.gates[row].verify::<Vesta>(row, &witness, &cs, &[]),
            Ok(())
        );
    }

    // check carry_lo is one
    assert_eq!(witness[7][16], PallasField::one());
    // check carry_mi is one
    assert_eq!(witness[8][16], PallasField::one());
}

#[test]
// Check it fails if given a wrong result
fn test_wrong_sum() {
    let cs = create_test_constraint_system_one_ffadd();

    let foreign_modulus = ForeignElement::<PallasField, 3>::new_from_be(FOREIGN_MOD);
    let left_input = ForeignElement::<PallasField, 3>::new_from_be(TIC);
    let right_input = ForeignElement::<PallasField, 3>::new_from_be(TOC);

    let mut witness = create_witness(vec![left_input, right_input], vec![ADD], foreign_modulus);

    // wrong result
    let all_ones_limb = PallasField::from(2u128.pow(88) - 1);
    witness[0][8] = all_ones_limb.clone();
    witness[0][17] = all_ones_limb.clone();

    view_witness(&witness);

    assert_eq!(
        cs.gates[16].verify_foreign_field_add::<Vesta>(0, &witness, &cs),
        Err(CircuitGateError::InvalidConstraint(
            GateType::ForeignFieldAdd
        )),
    );
}

/*
#[test]
// Test addends which are larger than the field but smaller than the limbs
// With the current witness code, we cannot generate a result ForignElement for this case because
// it will not fit. The foreign field helper will panic when trying to obtain `out`
fn test_larger_sum() {
    let cs = create_test_constraint_system_one_ffadd();

    let foreign_modulus = ForeignElement::<PallasField, 3>::new_from_be(FOREIGN_MOD);
    let left_input = ForeignElement::<PallasField, 3>::new_from_be(MAX_3_LIMBS);
    let right_input = ForeignElement::<PallasField, 3>::new_from_be(ZERO);

    let witness = create_witness(vec![left_input, right_input], vec![ADD], foreign_modulus);

    // highest limb of the result
    assert_eq!(
        cs.gates[10].verify_range_check::<Vesta>(0, &witness, &cs),
        Err(CircuitGateError::InvalidConstraint(GateType::RangeCheck1))
    );

    // highest limb of upper bound
    assert_eq!(
        cs.gates[14].verify_range_check::<Vesta>(0, &witness, &cs),
        Err(CircuitGateError::InvalidConstraint(GateType::RangeCheck1))
    );
}
*/

#[test]
// Test that numbers that do not fit inside the limb will fail
fn test_larger_than_limbs() {
    let cs = create_test_constraint_system_one_ffadd();
    let foreign_modulus = ForeignElement::<PallasField, 3>::new_from_be(FOREIGN_MOD);
    let mut left_input = ForeignElement::<PallasField, 3>::new_from_be(ZERO);
    let right_input = ForeignElement::<PallasField, 3>::new_from_be(ZERO);

    // Value 2^88 does not fit in 88 limbs
    left_input.limbs[0] = PallasField::from(2u128.pow(88));
    left_input.limbs[1] = PallasField::from(2u128.pow(88));
    left_input.limbs[2] = PallasField::from(2u128.pow(88));

    let witness = create_witness(vec![left_input, right_input], vec![ADD], foreign_modulus);

    assert_eq!(
        cs.gates[0].verify_range_check::<Vesta>(0, &witness, &cs),
        Err(CircuitGateError::InvalidConstraint(GateType::RangeCheck0))
    );

    assert_eq!(
        cs.gates[1].verify_range_check::<Vesta>(0, &witness, &cs),
        Err(CircuitGateError::InvalidConstraint(GateType::RangeCheck0))
    );

    assert_eq!(
        cs.gates[2].verify_range_check::<Vesta>(0, &witness, &cs),
        Err(CircuitGateError::InvalidConstraint(GateType::RangeCheck1))
    );
}
