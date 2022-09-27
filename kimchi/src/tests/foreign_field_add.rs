use crate::circuits::{
    constraints::ConstraintSystem,
    gate::{CircuitGate, CircuitGateError, GateType},
    polynomials::foreign_field_add::witness::create_witness,
    wires::Wire,
};
use ark_ec::AffineCurve;
use ark_ff::{One, Zero};
use mina_curves::pasta::{Pallas, Vesta};
use num_bigint::BigUint;
use num_traits::FromPrimitive;
use o1_utils::{
    foreign_field::{ForeignElement, FOREIGN_MOD},
    FieldHelpers,
};

type PallasField = <Pallas as AffineCurve>::BaseField;
type VestaField = <Vesta as AffineCurve>::BaseField;

/// Addition operation
static ADD: bool = true;

/// Subtraction operation
static SUB: bool = false;

/// Maximum value in the foreign field of seckp256k1
// BigEndian -> FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE FFFFFC2E
static MAX: &[u8] = &[
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFC, 0x2E,
];

/// Maximum value in the foreign field of Vesta
// BigEndian -> 40000000 00000000 00000000 00000000 224698fc 094cf91b 992d30ed 00000000
static MAX_VESTA: &[u8] = &[
    0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x22, 0x46, 0x98, 0xFC,
    0x09, 0x4C, 0xF9, 0x1B, 0x99, 0x2D, 0x30, 0xED, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// Maximum value in the foreign field of Pallas
// BigEndian -> 40000000 00000000 00000000 00000000 224698fc 0994a8dd 8c46eb21 00000000
static MAX_PALLAS: &[u8] = &[
    0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x22, 0x46, 0x98, 0xFC,
    0x09, 0x94, 0xA8, 0xDD, 0x8C, 0x46, 0xEB, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
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

fn create_test_constraint_system_ffadd(
    num: usize,
    modulus: BigUint,
) -> ConstraintSystem<PallasField> {
    let (mut next_row, mut gates) = CircuitGate::<PallasField>::create_foreign_field_add(0, num);

    // Temporary workaround for lookup-table/domain-size issue
    for _ in 0..(1 << 13) {
        gates.push(CircuitGate::zero(Wire::new(next_row)));
        next_row += 1;
    }

    ConstraintSystem::create(gates)
        .foreign_field_modulus(&Some(modulus))
        .build()
        .unwrap()
}

#[test]
// Add zero to zero. This checks that small amounts also get packed into limbs
fn test_zero_add() {
    let foreign_modulus = BigUint::from_bytes_be(FOREIGN_MOD);
    let cs = create_test_constraint_system_ffadd(1, foreign_modulus.clone());

    let left_input = BigUint::from_bytes_be(ZERO);
    let right_input = BigUint::from_bytes_be(ZERO);

    let witness = create_witness(vec![left_input, right_input], vec![ADD], foreign_modulus);

    for row in 0..=18 {
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
    let foreign_modulus = BigUint::from_bytes_be(FOREIGN_MOD);
    let cs = create_test_constraint_system_ffadd(1, foreign_modulus.clone());

    let left_input = BigUint::from_bytes_be(FOR_MOD_BOT);
    let right_input = BigUint::from_bytes_be(FOR_MOD_TOP);

    let witness = create_witness(vec![left_input, right_input], vec![ADD], foreign_modulus);

    for row in 0..=18 {
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
    let foreign_modulus = BigUint::from_bytes_be(FOREIGN_MOD);
    let native_modulus = PallasField::modulus_biguint();
    let cs = create_test_constraint_system_ffadd(1, foreign_modulus.clone());

    let one = BigUint::new(vec![1u32]);
    let mod_minus_one = native_modulus.clone() - one.clone();
    let left_input = BigUint::from_bytes_be(ONE);
    let right_input = mod_minus_one;

    let witness = create_witness(
        vec![left_input, right_input],
        vec![ADD],
        foreign_modulus.clone(),
    );

    for row in 0..=18 {
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

    for row in 16..=18 {
        assert_eq!(
            cs.gates[row].verify::<Vesta>(row, &witness, &cs, &[]),
            Ok(())
        );
    }

    // Check result is the native modulus
    let native_limbs = ForeignElement::<PallasField, 3>::from_biguint(native_modulus);
    assert_eq!(witness[0][17], *native_limbs.lo());
    assert_eq!(witness[1][17], *native_limbs.mi());
    assert_eq!(witness[2][17], *native_limbs.hi());
}

#[test]
fn test_one_plus_one() {
    let foreign_modulus = BigUint::from_bytes_be(FOREIGN_MOD);
    let cs = create_test_constraint_system_ffadd(1, foreign_modulus.clone());

    let left_input = BigUint::from_bytes_be(ONE);
    let right_input = BigUint::from_bytes_be(ONE);

    let witness = create_witness(vec![left_input, right_input], vec![ADD], foreign_modulus);

    for row in 0..=18 {
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
    let foreign_modulus = BigUint::from_bytes_be(FOREIGN_MOD);
    let cs = create_test_constraint_system_ffadd(1, foreign_modulus.clone());

    let left_input = BigUint::from_bytes_be(MAX);
    let right_input = BigUint::from_bytes_be(MAX);

    let witness = create_witness(
        vec![left_input, right_input],
        vec![ADD],
        foreign_modulus.clone(),
    );

    for row in 0..=18 {
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

    for row in 16..=18 {
        assert_eq!(
            cs.gates[row].verify::<Vesta>(row, &witness, &cs, &[]),
            Ok(())
        );
    }

    // compute result in the foreign field after taking care of the exceeding bits
    let sum = BigUint::from_bytes_be(MAX) + BigUint::from_bytes_be(MAX);
    let sum_mod = sum - foreign_modulus.clone();
    let sum_mod_limbs = ForeignElement::<PallasField, 3>::from_biguint(sum_mod);
    assert_eq!(witness[7][16], PallasField::one()); // field overflow
    assert_eq!(witness[0][17], *sum_mod_limbs.lo()); // result limbs
    assert_eq!(witness[1][17], *sum_mod_limbs.mi());
    assert_eq!(witness[2][17], *sum_mod_limbs.hi());
}

#[test]
// test 0 - 1 where (-1) is in the foreign field
// this is tested first as 0 + neg(1)
// and then as 0 - 1
// and it is checked that in both cases the result is the same
fn test_zero_minus_one() {
    let foreign_modulus = BigUint::from_bytes_be(FOREIGN_MOD);
    let cs = create_test_constraint_system_ffadd(1, foreign_modulus.clone());

    // FIRST AS NEG

    // big uint of the number 1
    let big_one = BigUint::from_u32(1).unwrap();

    let left_input = BigUint::from_bytes_be(ZERO);
    let right_foreign_neg =
        ForeignElement::<PallasField, 3>::from_biguint(big_one.clone()).neg(&foreign_modulus);
    let right_input_neg = right_foreign_neg.to_big();

    let witness_neg = create_witness(
        vec![left_input.clone(), right_input_neg],
        vec![ADD],
        foreign_modulus.clone(),
    );

    for row in 0..=18 {
        assert_eq!(
            cs.gates[row].verify_witness::<Vesta>(
                row,
                &witness_neg,
                &cs,
                &witness_neg[0][0..cs.public].to_vec()
            ),
            Ok(())
        );
    }

    for row in 16..=18 {
        assert_eq!(
            cs.gates[row].verify::<Vesta>(row, &witness_neg, &cs, &[]),
            Ok(())
        );
    }
    assert_eq!(witness_neg[0][17], *right_foreign_neg.lo());
    assert_eq!(witness_neg[1][17], *right_foreign_neg.mi());
    assert_eq!(witness_neg[2][17], *right_foreign_neg.hi());

    // NEXT AS SUB

    let right_input_sub = BigUint::from_bytes_be(ONE);

    let witness_sub = create_witness(
        vec![left_input, right_input_sub],
        vec![SUB],
        foreign_modulus.clone(),
    );

    for row in 0..=18 {
        assert_eq!(
            cs.gates[row].verify_witness::<Vesta>(
                row,
                &witness_sub,
                &cs,
                &witness_sub[0][0..cs.public].to_vec()
            ),
            Ok(())
        );
    }

    for row in 16..=18 {
        assert_eq!(
            cs.gates[row].verify::<Vesta>(row, &witness_sub, &cs, &[]),
            Ok(())
        );
    }
    assert_eq!(witness_sub[0][17], *right_foreign_neg.lo());
    assert_eq!(witness_sub[1][17], *right_foreign_neg.mi());
    assert_eq!(witness_sub[2][17], *right_foreign_neg.hi());
}

#[test]
// test 1 - 1 + 1 where (-1) is in the foreign field
// the first check is done with sub(1, 1) and then with add(neg(neg(1)))
fn test_one_minus_one_plus_one() {
    let foreign_modulus = BigUint::from_bytes_be(FOREIGN_MOD);
    let cs = create_test_constraint_system_ffadd(2, foreign_modulus.clone());

    // big uint of the number 1
    let big_one = BigUint::from_u32(1).unwrap();

    let left_input = big_one.clone();
    let minus_one = big_one.clone();
    let neg_neg_one = ForeignElement::<PallasField, 3>::from_biguint(big_one)
        .neg(&foreign_modulus)
        .neg(&foreign_modulus)
        .to_big();

    let witness = create_witness(
        vec![left_input, minus_one, neg_neg_one],
        vec![SUB, ADD],
        foreign_modulus,
    );

    for row in 0..=26 {
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

    for row in 24..=26 {
        assert_eq!(
            cs.gates[row].verify::<Vesta>(row, &witness, &cs, &[]),
            Ok(())
        );
    }
    // intermediate 1 - 1 should be zero
    assert_eq!(witness[0][25], PallasField::zero());
    assert_eq!(witness[1][25], PallasField::zero());
    assert_eq!(witness[2][25], PallasField::zero());
    // final 0 + 1 should be 1
    assert_eq!(witness[0][26], PallasField::one());
    assert_eq!(witness[1][26], PallasField::zero());
    assert_eq!(witness[2][26], PallasField::zero());
}

#[test]
// test -1-1 where (-1) is in the foreign field
// tested as neg(1) + neg(1)
fn test_minus_minus() {
    let foreign_modulus = BigUint::from_bytes_be(FOREIGN_MOD);
    let cs = create_test_constraint_system_ffadd(1, foreign_modulus.clone());

    // big uint of the number 1
    let big_one = BigUint::from_u32(1).unwrap();
    let big_two = big_one.clone() + big_one.clone();

    let left_input = ForeignElement::<PallasField, 3>::from_biguint(big_one.clone())
        .neg(&foreign_modulus)
        .to_big();
    let right_input = ForeignElement::<PallasField, 3>::from_biguint(big_one)
        .neg(&foreign_modulus)
        .to_big();

    let witness = create_witness(
        vec![left_input, right_input],
        vec![ADD],
        foreign_modulus.clone(),
    );

    for row in 0..=18 {
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

    for row in 16..=18 {
        assert_eq!(
            cs.gates[row].verify::<Vesta>(row, &witness, &cs, &[]),
            Ok(())
        );
    }

    let for_neg_two = ForeignElement::<PallasField, 3>::from_biguint(big_two).neg(&foreign_modulus);

    assert_eq!(witness[0][17], *for_neg_two.lo());
    assert_eq!(witness[1][17], *for_neg_two.mi());
    assert_eq!(witness[2][17], *for_neg_two.hi());
}

#[test]
// test when the low carry is minus one
fn test_neg_carry_lo() {
    let foreign_modulus = BigUint::from_bytes_be(FOREIGN_MOD);
    let cs = create_test_constraint_system_ffadd(1, foreign_modulus.clone());

    let left_input = BigUint::from_bytes_be(OVF_NEG_LO);
    let right_input = BigUint::from_bytes_be(OVF_NEG_LO);

    let witness = create_witness(vec![left_input, right_input], vec![ADD], foreign_modulus);

    for row in 0..=18 {
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

    for row in 16..=18 {
        assert_eq!(
            cs.gates[row].verify::<Vesta>(row, &witness, &cs, &[]),
            Ok(())
        );
    }
    assert_eq!(witness[8][16], -PallasField::one());
    assert_eq!(witness[9][16], PallasField::zero());
}

#[test]
// test when the middle carry is minus one
fn test_neg_carry_mi() {
    let foreign_modulus = BigUint::from_bytes_be(FOREIGN_MOD);
    let cs = create_test_constraint_system_ffadd(1, foreign_modulus.clone());

    let left_input = BigUint::from_bytes_be(OVF_NEG_MI);
    let right_input = BigUint::from_bytes_be(OVF_NEG_MI);

    let witness = create_witness(vec![left_input, right_input], vec![ADD], foreign_modulus);

    for row in 0..=18 {
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

    for row in 16..=18 {
        assert_eq!(
            cs.gates[row].verify::<Vesta>(row, &witness, &cs, &[]),
            Ok(())
        );
    }
    assert_eq!(witness[8][16], PallasField::zero());
    assert_eq!(witness[9][16], -PallasField::one());
}

#[test]
// test when there is negative low carry and 0 middle limb (carry bit propagates)
fn test_zero_mi() {
    let foreign_modulus = BigUint::from_bytes_be(FOREIGN_MOD);
    let cs = create_test_constraint_system_ffadd(1, foreign_modulus.clone());

    let left_input = BigUint::from_bytes_be(OVF_ZERO_MI_NEG_LO);
    let right_input = BigUint::from_bytes_be(OVF_ZERO_MI_NEG_LO);

    let witness = create_witness(vec![left_input, right_input], vec![ADD], foreign_modulus);

    for row in 0..=18 {
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

    for row in 16..=18 {
        assert_eq!(
            cs.gates[row].verify::<Vesta>(row, &witness, &cs, &[]),
            Ok(())
        );
    }
    assert_eq!(witness[8][16], -PallasField::one());
    assert_eq!(witness[9][16], -PallasField::one());
}

#[test]
// test when the both carries are minus one
fn test_neg_carries() {
    let foreign_modulus = BigUint::from_bytes_be(FOREIGN_MOD);
    let cs = create_test_constraint_system_ffadd(1, foreign_modulus.clone());

    let left_input = BigUint::from_bytes_be(OVF_NEG_BOTH);
    let right_input = BigUint::from_bytes_be(OVF_ZERO_MI_NEG_LO);

    let witness = create_witness(vec![left_input, right_input], vec![ADD], foreign_modulus);

    for row in 0..=18 {
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

    for row in 16..=18 {
        assert_eq!(
            cs.gates[row].verify::<Vesta>(row, &witness, &cs, &[]),
            Ok(())
        );
    }
    assert_eq!(witness[8][16], -PallasField::one());
    assert_eq!(witness[9][16], -PallasField::one());
}

#[test]
// test the upperbound of the result
fn test_upperbound() {
    let foreign_modulus = BigUint::from_bytes_be(FOREIGN_MOD);
    let cs = create_test_constraint_system_ffadd(1, foreign_modulus.clone());

    let left_input = BigUint::from_bytes_be(OVF_LESS_HI_LEFT);
    let right_input = BigUint::from_bytes_be(OVF_LESS_HI_RIGHT);

    let witness = create_witness(vec![left_input, right_input], vec![ADD], foreign_modulus);

    for row in 0..=18 {
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

    for row in 16..=18 {
        assert_eq!(
            cs.gates[row].verify::<Vesta>(row, &witness, &cs, &[]),
            Ok(())
        );
    }
}

#[test]
// test a carry that nullifies in the low limb
fn test_null_lo_carry() {
    let foreign_modulus = BigUint::from_bytes_be(FOREIGN_MOD);
    let cs = create_test_constraint_system_ffadd(1, foreign_modulus.clone());

    let left_input = BigUint::from_bytes_be(MAX);
    let right_input = BigUint::from_bytes_be(NULL_CARRY_LO);

    let witness = create_witness(vec![left_input, right_input], vec![ADD], foreign_modulus);

    for row in 0..=18 {
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

    for row in 16..=18 {
        assert_eq!(
            cs.gates[row].verify::<Vesta>(row, &witness, &cs, &[]),
            Ok(())
        );
    }
    assert_eq!(witness[8][16], PallasField::zero());
}

#[test]
// test a carry that nullifies in the mid limb
fn test_null_mi_carry() {
    let foreign_modulus = BigUint::from_bytes_be(FOREIGN_MOD);
    let cs = create_test_constraint_system_ffadd(1, foreign_modulus.clone());

    let left_input = BigUint::from_bytes_be(MAX);
    let right_input = BigUint::from_bytes_be(NULL_CARRY_MI);

    let witness = create_witness(vec![left_input, right_input], vec![ADD], foreign_modulus);

    for row in 0..=18 {
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

    for row in 16..=18 {
        assert_eq!(
            cs.gates[row].verify::<Vesta>(row, &witness, &cs, &[]),
            Ok(())
        );
    }
    assert_eq!(witness[9][16], PallasField::zero());
}

#[test]
// test a carry that nullifies in the mid limb
fn test_null_both_carry() {
    let foreign_modulus = BigUint::from_bytes_be(FOREIGN_MOD);
    let cs = create_test_constraint_system_ffadd(1, foreign_modulus.clone());

    let left_input = BigUint::from_bytes_be(MAX);
    let right_input = BigUint::from_bytes_be(NULL_CARRY_BOTH);

    let witness = create_witness(vec![left_input, right_input], vec![ADD], foreign_modulus);

    for row in 0..=18 {
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

    for row in 16..=18 {
        assert_eq!(
            cs.gates[row].verify::<Vesta>(row, &witness, &cs, &[]),
            Ok(())
        );
    }
    assert_eq!(witness[8][16], PallasField::zero());
    assert_eq!(witness[9][16], PallasField::zero());
}

#[test]
// test sums without carry bits in any limb
fn test_no_carry_limbs() {
    let foreign_modulus = BigUint::from_bytes_be(FOREIGN_MOD);
    let cs = create_test_constraint_system_ffadd(1, foreign_modulus.clone());

    let left_input = BigUint::from_bytes_be(TIC);
    let right_input = BigUint::from_bytes_be(TOC);

    let witness = create_witness(vec![left_input, right_input], vec![ADD], foreign_modulus);

    for row in 0..=18 {
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

    for row in 16..=18 {
        assert_eq!(
            cs.gates[row].verify::<Vesta>(row, &witness, &cs, &[]),
            Ok(())
        );
    }

    // check carry_lo is zero
    assert_eq!(witness[8][16], PallasField::zero());
    // check carry_mi is zero
    assert_eq!(witness[9][16], PallasField::zero());
    // check middle limb is all ones
    let all_one_limb = PallasField::from(2u128.pow(88) - 1);
    assert_eq!(witness[1][17], all_one_limb);
}

#[test]
// test sum with carry only in low part
fn test_pos_carry_limb_lo() {
    let foreign_modulus = BigUint::from_bytes_be(FOREIGN_MOD);
    let cs = create_test_constraint_system_ffadd(1, foreign_modulus.clone());

    let left_input = BigUint::from_bytes_be(TIC);
    let right_input = BigUint::from_bytes_be(TOC_LO);

    let witness = create_witness(vec![left_input, right_input], vec![ADD], foreign_modulus);

    for row in 0..=18 {
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

    for row in 16..=18 {
        assert_eq!(
            cs.gates[row].verify::<Vesta>(row, &witness, &cs, &[]),
            Ok(())
        );
    }

    // check carry_lo is one
    assert_eq!(witness[8][16], PallasField::one());
    // check carry_mi is zero
    assert_eq!(witness[9][16], PallasField::zero());
}

#[test]
fn test_pos_carry_limb_mid() {
    let foreign_modulus = BigUint::from_bytes_be(FOREIGN_MOD);
    let cs = create_test_constraint_system_ffadd(1, foreign_modulus.clone());

    let left_input = BigUint::from_bytes_be(TIC);
    let right_input = BigUint::from_bytes_be(TOC_MI);

    let witness = create_witness(vec![left_input, right_input], vec![ADD], foreign_modulus);

    for row in 0..=18 {
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

    for row in 16..=18 {
        assert_eq!(
            cs.gates[row].verify::<Vesta>(row, &witness, &cs, &[]),
            Ok(())
        );
    }

    // check carry_lo is one
    assert_eq!(witness[8][16], PallasField::zero());
    // check carry_mi is zero
    assert_eq!(witness[9][16], PallasField::one());
}

#[test]
fn test_pos_carry_limb_lo_mid() {
    let foreign_modulus = BigUint::from_bytes_be(FOREIGN_MOD);
    let cs = create_test_constraint_system_ffadd(1, foreign_modulus.clone());

    let left_input = BigUint::from_bytes_be(TIC);
    let right_input = BigUint::from_bytes_be(TOC_TWO);

    let witness = create_witness(vec![left_input, right_input], vec![ADD], foreign_modulus);

    for row in 0..=18 {
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

    for row in 16..=18 {
        assert_eq!(
            cs.gates[row].verify::<Vesta>(row, &witness, &cs, &[]),
            Ok(())
        );
    }

    // check carry_lo is one
    assert_eq!(witness[8][16], PallasField::one());
    // check carry_mi is one
    assert_eq!(witness[9][16], PallasField::one());
}

#[test]
// Check it fails if given a wrong result
fn test_wrong_sum() {
    let foreign_modulus = BigUint::from_bytes_be(FOREIGN_MOD);
    let cs = create_test_constraint_system_ffadd(1, foreign_modulus.clone());

    let left_input = BigUint::from_bytes_be(TIC);
    let right_input = BigUint::from_bytes_be(TOC);

    let mut witness = create_witness(vec![left_input, right_input], vec![ADD], foreign_modulus);

    for row in 0..=18 {
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
// Test subtraction of the foreign field
fn test_zero_sub_fmod() {
    let foreign_modulus = BigUint::from_bytes_be(FOREIGN_MOD);
    let cs = create_test_constraint_system_ffadd(1, foreign_modulus.clone());

    let left_input = BigUint::from_bytes_be(ZERO);
    let right_input = BigUint::from_bytes_be(FOREIGN_MOD);

    let witness = create_witness(vec![left_input, right_input], vec![SUB], foreign_modulus);

    for row in 0..=18 {
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

    for row in 16..=18 {
        assert_eq!(
            cs.gates[row].verify::<Vesta>(row, &witness, &cs, &[]),
            Ok(())
        );
    }

    // -f should be 0 mod f
    assert_eq!(witness[0][17], PallasField::zero());
    assert_eq!(witness[1][17], PallasField::zero());
    assert_eq!(witness[2][17], PallasField::zero());
}

#[test]
// Test subtraction of the foreign field maximum value
fn test_zero_sub_fmax() {
    let foreign_modulus = BigUint::from_bytes_be(FOREIGN_MOD);
    let cs = create_test_constraint_system_ffadd(1, foreign_modulus.clone());

    let left_input = BigUint::from_bytes_be(ZERO);
    let right_input = BigUint::from_bytes_be(MAX);

    let witness = create_witness(
        vec![left_input, right_input.clone()],
        vec![SUB],
        foreign_modulus.clone(),
    );

    for row in 0..=18 {
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

    for row in 16..=18 {
        assert_eq!(
            cs.gates[row].verify::<Vesta>(row, &witness, &cs, &[]),
            Ok(())
        );
    }

    let negated = ForeignElement::<PallasField, 3>::from_biguint(right_input).neg(&foreign_modulus);

    assert_eq!(witness[0][17], *negated.lo());
    assert_eq!(witness[1][17], *negated.mi());
    assert_eq!(witness[2][17], *negated.hi());
}

#[test]
// Test with Pasta curves where foreign field is smaller than the native field
fn test_pasta_add_max_vesta() {
    // The order of the Pallas curve is 0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000001.
    // The order of the Vesta curve is  0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001.
    let vesta_modulus = VestaField::modulus_biguint();

    let cs = create_test_constraint_system_ffadd(1, vesta_modulus.clone());

    let left_input = BigUint::from_bytes_be(ZERO);
    let right_input = BigUint::from_bytes_be(MAX_VESTA);

    let witness = create_witness(
        vec![left_input, right_input.clone()],
        vec![ADD],
        vesta_modulus.clone(),
    );

    for row in 0..=18 {
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

    for row in 16..=18 {
        assert_eq!(
            cs.gates[row].verify::<Vesta>(row, &witness, &cs, &[]),
            Ok(())
        );
    }
    let right = right_input % vesta_modulus;
    let foreign_right = ForeignElement::<PallasField, 3>::from_biguint(right);

    assert_eq!(witness[0][17], *foreign_right.lo());
    assert_eq!(witness[1][17], *foreign_right.mi());
    assert_eq!(witness[2][17], *foreign_right.hi());
}

#[test]
// Test with Pasta curves where foreign field is smaller than the native field
fn test_pasta_sub_max_vesta() {
    // The order of the Pallas curve is 0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000001.
    // The order of the Vesta curve is  0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001.
    let vesta_modulus = VestaField::modulus_biguint();

    let cs = create_test_constraint_system_ffadd(1, vesta_modulus.clone());

    let left_input = BigUint::from_bytes_be(ZERO);
    let right_input = BigUint::from_bytes_be(MAX_VESTA);

    let witness = create_witness(
        vec![left_input, right_input.clone()],
        vec![SUB],
        vesta_modulus.clone(),
    );

    for row in 0..=18 {
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

    for row in 16..=18 {
        assert_eq!(
            cs.gates[row].verify::<Vesta>(row, &witness, &cs, &[]),
            Ok(())
        );
    }

    let neg_max_vesta =
        ForeignElement::<PallasField, 3>::from_biguint(right_input).neg(&vesta_modulus);

    assert_eq!(witness[0][17], *neg_max_vesta.lo());
    assert_eq!(witness[1][17], *neg_max_vesta.mi());
    assert_eq!(witness[2][17], *neg_max_vesta.hi());
}

#[test]
// Test with Pasta curves where foreign field is smaller than the native field
fn test_pasta_add_max_pallas() {
    // The order of the Pallas curve is 0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000001.
    // The order of the Vesta curve is  0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001.
    let vesta_modulus = VestaField::modulus_biguint();

    let cs = create_test_constraint_system_ffadd(1, vesta_modulus.clone());

    let left_input = BigUint::from_bytes_be(ZERO);
    let right_input = BigUint::from_bytes_be(MAX_PALLAS);

    let witness = create_witness(
        vec![left_input, right_input.clone()],
        vec![ADD],
        vesta_modulus.clone(),
    );

    for row in 0..=18 {
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

    for row in 16..=18 {
        assert_eq!(
            cs.gates[row].verify::<Vesta>(row, &witness, &cs, &[]),
            Ok(())
        );
    }

    let right = right_input % vesta_modulus;
    let foreign_right = ForeignElement::<PallasField, 3>::from_biguint(right);

    assert_eq!(witness[0][17], *foreign_right.lo());
    assert_eq!(witness[1][17], *foreign_right.mi());
    assert_eq!(witness[2][17], *foreign_right.hi());
}

#[test]
// Test with Pasta curves where foreign field is smaller than the native field
fn test_pasta_sub_max_pallas() {
    // The order of the Pallas curve is 0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000001.
    // The order of the Vesta curve is  0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001.
    let vesta_modulus = VestaField::modulus_biguint();

    let cs = create_test_constraint_system_ffadd(1, vesta_modulus.clone());

    let left_input = BigUint::from_bytes_be(ZERO);
    let right_input = BigUint::from_bytes_be(MAX_PALLAS);

    let witness: [Vec<PallasField>; 15] = create_witness(
        vec![left_input, right_input.clone()],
        vec![SUB],
        vesta_modulus.clone(),
    );

    for row in 0..=18 {
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

    for row in 16..=18 {
        assert_eq!(
            cs.gates[row].verify::<Vesta>(row, &witness, &cs, &[]),
            Ok(())
        );
    }

    let neg_max_pallas =
        ForeignElement::<PallasField, 3>::from_biguint(right_input).neg(&vesta_modulus);

    assert_eq!(witness[0][17], *neg_max_pallas.lo());
    assert_eq!(witness[1][17], *neg_max_pallas.mi());
    assert_eq!(witness[2][17], *neg_max_pallas.hi());
}

/*
#[test]
// Test addends which are larger than the field but smaller than the limbs
// With the current witness code, we cannot generate a result ForignElement for this case because
// it will not fit. The foreign field helper will panic when trying to obtain `out`
fn test_larger_sum() {
    let cs = create_test_constraint_system_one_ffadd();

    let foreign_modulus = ForeignElement::<PallasField, 3>::from_be(FOREIGN_MOD);
    let left_input = ForeignElement::<PallasField, 3>::from_be(MAX_3_LIMBS);
    let right_input = ForeignElement::<PallasField, 3>::from_be(ZERO);

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


#[test]
// Test that numbers that do not fit inside the limb will fail
// when input is BigUint we prevent this from happenning
fn test_larger_than_limbs() {
    let cs = create_test_constraint_system_one_ffadd();
    let foreign_modulus = BigUint::from_bytes_be(FOREIGN_MOD);
    let right_input = BigUint::from_bytes_be(ZERO);

    // Value 2^88 does not fit in 3 limbs
    let left_input = BigUint::from(2u128.pow(88)).pow(3);

    let mut witness = create_witness(vec![left_input, right_input], vec![ADD], foreign_modulus);

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
*/
