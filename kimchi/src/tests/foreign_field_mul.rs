use crate::{
    circuits::{
        gate::CircuitGate,
        polynomials::foreign_field_mul::{self},
        wires::Wire,
    },
    prover_index::testing::new_index_for_test_with_lookups,
    prover_index::ProverIndex,
};
use ark_ec::AffineCurve;
use ark_ff::Zero;
use mina_curves::pasta::{Fp, Pallas, Vesta};
use num_bigint::BigUint;
use o1_utils::foreign_field::{ForeignElement, SECP256K1_MOD};

type PallasField = <Pallas as AffineCurve>::BaseField;

// foreign modulus: BigEndian -> FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE FFFFFC2F
// -> limbs: [FFFFFFFFFFFFFFFFFFFF] [FFFFFFFFFFFFFFFFFFFF] [FFFFFFFFFFFFFFFEFFFFFC2F]
// = 255,  255,  255,  255,  255,  255,  255,  255,  255,  255,  255,  255,  255,  255,  255,  255,
//   255,  255,  255,  255,  255,  255,  255,  255,  255,  255,  255,  254,  255,  255,  252,   47

/// Maximum value in the foreign field
// BigEndian -> FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE FFFFFC2E
// = 255,  255,  255,  255,  255,  255,  255,  255,  255,  255,  255,  255,  255,  255,  255,  255,
//   255,  255,  255,  255,  255,  255,  255,  255,  255,  255,  255,  254,  255,  255,  252,   46
static MAX_FOR: &[u8] = &[
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFC, 0x2E,
];

/// Maximum value whose square fits in foreign field
// 340282366920938463463374607431768211455
// BigEndian -> FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF
static SQR_FOR: &[u8] = &[
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
];

/// Maximum value in the native field
// BigEndian -> 40000000 00000000 00000000 00000000 224698FC 094CF91B 992D30ED 00000000
// =  64,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
//    34,  255,  255,  255,  255,  255,  255,  255,  255,  255,  255,  254,  255,  255,  252,   46
static MAX_NAT: &[u8] = &[
    0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x22, 0x46, 0x98, 0xFC, 0x09, 0x4C, 0xF9, 0x1B, 0x99, 0x2D, 0x30, 0xED, 0x00, 0x00, 0x00, 0x00,
];

/// Maximum value whose square fits in native field
// 170141183460469231731687303715884105728
// BigEndian -> 80000000 00000000 00000000 00000000
static SQR_NAT: &[u8] = &[
    0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// The zero byte
static ZERO: &[u8] = &[0x00];

/// The one byte
static ONE: &[u8] = &[0x01];

fn create_test_prover_index(public_size: usize) -> ProverIndex<Vesta> {
    let (mut next_row, mut gates) = CircuitGate::<Fp>::create_foreign_field_mul(0);

    // Temporary workaround for lookup-table/domain-size issue
    // TODO: shouldnt this be 1 << 12
    for _ in 0..(1 << 13) {
        gates.push(CircuitGate::zero(Wire::new(next_row)));
        next_row += 1;
    }

    new_index_for_test_with_lookups(
        gates,
        public_size,
        0,
        vec![foreign_field_mul::gadget::lookup_table()],
        None,
        Some(BigUint::from_bytes_be(SECP256K1_MOD)),
    )
}

#[test]
// Multiply zeroes. This checks that small amounts also get packed into limbs
fn test_zero_mul() {
    let prover_index = create_test_prover_index(0);

    let foreign_modulus = ForeignElement::<PallasField, 3>::from_be(SECP256K1_MOD);

    let left_input = ForeignElement::<PallasField, 3>::new([
        PallasField::zero(),
        PallasField::zero(),
        PallasField::zero(),
    ]);
    let right_input = ForeignElement::<PallasField, 3>::from_be(ZERO);

    let witness =
        foreign_field_mul::witness::create_witness(left_input, right_input, foreign_modulus.clone());

    assert_eq!(
        Ok(()),
        foreign_field_mul::witness::check_witness(&witness, &foreign_modulus)
    );

    for row in 0..22 {
        assert_eq!(
            prover_index.cs.gates[row].verify::<Vesta>(row, &witness, &prover_index.cs, &[]),
            Ok(())
        );
    }

    // check quotient and remainder values are zero
    assert_eq!(witness[1][21], PallasField::zero());
    assert_eq!(witness[2][21], PallasField::zero());
    assert_eq!(witness[3][21], PallasField::zero());
    assert_eq!(witness[4][21], PallasField::zero());
    assert_eq!(witness[5][21], PallasField::zero());
    assert_eq!(witness[6][21], PallasField::zero());
}

#[test]
// Test multiplication of largest foreign element and one
fn test_one_mul() {
    let prover_index = create_test_prover_index(0);

    let foreign_modulus = ForeignElement::<PallasField, 3>::from_be(SECP256K1_MOD);
    let left_input = ForeignElement::<PallasField, 3>::from_be(MAX_FOR);
    let right_input = ForeignElement::<PallasField, 3>::from_be(ONE);

    let witness =
        foreign_field_mul::witness::create_witness(left_input.clone(), right_input, foreign_modulus.clone());

    assert_eq!(
        Ok(()),
        foreign_field_mul::witness::check_witness(&witness, &foreign_modulus)
    );

    for row in 0..=19 {
        assert_eq!(
            prover_index.cs.gates[row].verify::<Vesta>(row, &witness, &prover_index.cs, &[]),
            Ok(())
        );
    }

    // check quotient is zero and remainder is MAX_FOR
    assert_eq!(witness[1][21], PallasField::zero());
    assert_eq!(witness[2][21], PallasField::zero());
    assert_eq!(witness[3][21], PallasField::zero());
    assert_eq!(witness[4][21], left_input[0]);
    assert_eq!(witness[5][21], left_input[1]);
    assert_eq!(witness[6][21], left_input[2]);
}
#[test]
// Test maximum values whose squaring fits in the native field
// m^2 = q * f + r -> q should be 0 and r should be m^2 < n < f
fn test_max_native_square() {
    //let prover_index = create_test_prover_index(0);
    let foreign_modulus = ForeignElement::<PallasField, 3>::from_be(SECP256K1_MOD);
    let left_input = ForeignElement::<PallasField, 3>::from_be(SQR_NAT);
    let right_input = ForeignElement::<PallasField, 3>::from_be(SQR_NAT);

    let witness = foreign_field_mul::witness::create_witness(
        left_input.clone(),
        right_input,
        foreign_modulus.clone(),
    );

    assert_eq!(
        Ok(()),
        foreign_field_mul::witness::check_witness(&witness, &foreign_modulus)
    );

    /*
    for row in 0..20 {
        assert_eq!(
            prover_index.cs.gates[row].verify::<Vesta>(row, &witness, &prover_index.cs, &[]),
            Ok(())
        );
    }*/

    let multiplicand = left_input.to_biguint();
    let square = multiplicand.pow(2u32);
    let product = ForeignElement::<PallasField, 3>::from_biguint(square);

    // check quotient is zero and remainder is the square
    assert_eq!(witness[1][21], PallasField::zero());
    assert_eq!(witness[2][21], PallasField::zero());
    assert_eq!(witness[3][21], PallasField::zero());
    assert_eq!(witness[4][21], product[0]);
    assert_eq!(witness[5][21], product[1]);
    assert_eq!(witness[6][21], product[2]);
}

#[test]
// Test maximum values whose squaring fits in the foreign field
// g^2 = q * f + r -> q should be 0 and r should be g^2 < f
fn test_max_foreign_square() {
    //let prover_index = create_test_prover_index(0);
    let foreign_modulus = ForeignElement::<PallasField, 3>::from_be(SECP256K1_MOD);
    let left_input = ForeignElement::<PallasField, 3>::from_be(SQR_FOR);
    let right_input = ForeignElement::<PallasField, 3>::from_be(SQR_FOR);

    let witness = foreign_field_mul::witness::create_witness(
        left_input.clone(),
        right_input,
        foreign_modulus.clone(),
    );

    assert_eq!(
        Ok(()),
        foreign_field_mul::witness::check_witness(&witness, &foreign_modulus)
    );
    /*
        for row in 0..22 {
            assert_eq!(
                prover_index.cs.gates[row].verify::<Vesta>(row, &witness, &prover_index.cs, &[]),
                Ok(())
            );
        }
    */
    let multiplicand = left_input.to_biguint();
    let square = multiplicand.pow(2u32);
    let product = ForeignElement::<PallasField, 3>::from_biguint(square);

    // check quotient is zero and remainder is the square
    assert_eq!(witness[1][21], PallasField::zero());
    assert_eq!(witness[2][21], PallasField::zero());
    assert_eq!(witness[3][21], PallasField::zero());
    assert_eq!(witness[4][21], product[0]);
    assert_eq!(witness[5][21], product[1]);
    assert_eq!(witness[6][21], product[2]);
}

#[test]
// Test squaring of the maximum native field values
// (n - 1) * (n - 1) = q * f + r
fn test_max_native_multiplicands() {
    //let prover_index = create_test_prover_index(0);
    let foreign_modulus = ForeignElement::<PallasField, 3>::from_be(SECP256K1_MOD);
    let left_input = ForeignElement::<PallasField, 3>::from_be(MAX_NAT);
    let right_input = ForeignElement::<PallasField, 3>::from_be(MAX_NAT);

    let witness =
        foreign_field_mul::witness::create_witness(left_input, right_input, foreign_modulus.clone());

    // fails zer
    assert_eq!(
        Ok(()),
        foreign_field_mul::witness::check_witness(&witness, &foreign_modulus)
    );

    /*for row in 0..22 {
        assert_eq!(
            cs.gates[row].verify::<Vesta>(row, &witness, &cs, &[]),
            Ok(())
        );
    }*/
}

#[test]
// Test squaring of the maximum foreign field values
// ( f - 1) * (f - 1) = f^2 - 2f + 1 = f * (f - 2) + 1
fn test_max_foreign_multiplicands() {
    //let prover_index = create_test_prover_index(0);
    let foreign_modulus = ForeignElement::<PallasField, 3>::from_be(SECP256K1_MOD);
    let left_input = ForeignElement::<PallasField, 3>::from_be(MAX_FOR);
    let right_input = ForeignElement::<PallasField, 3>::from_be(MAX_FOR);

    let witness =
        foreign_field_mul::witness::create_witness(left_input, right_input, foreign_modulus.clone());

    assert_eq!(
        Ok(()),
        foreign_field_mul::witness::check_witness(&witness, &foreign_modulus)
    );
}
