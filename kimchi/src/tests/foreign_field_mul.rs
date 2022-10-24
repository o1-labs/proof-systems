use crate::{
    circuits::{
        constraints::ConstraintSystem,
        gate::CircuitGate,
        polynomial::COLUMNS,
        polynomials::foreign_field_mul::{self},
        wires::Wire,
    },
    tests::framework::TestFramework,
};
use ark_ec::AffineCurve;
use ark_ff::Zero;
use mina_curves::pasta::{Fp, Pallas, Vesta};
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
static SECP256K1_MAX: &[u8] = &[
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFC, 0x2E,
];

/// Maximum value whose square fits in foreign field
// 340282366920938463463374607431768211455
// BigEndian -> FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF
static SECP256K1_SQR: &[u8] = &[
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
];

/// Maximum value in the native field
// BigEndian -> 40000000 00000000 00000000 00000000 224698FC 094CF91B 992D30ED 00000000
// =  64,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
//    34,  255,  255,  255,  255,  255,  255,  255,  255,  255,  255,  254,  255,  255,  252,   46
static _PALLAS_MAX: &[u8] = &[
    0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x22, 0x46, 0x98, 0xFC, 0x09, 0x4C, 0xF9, 0x1B, 0x99, 0x2D, 0x30, 0xED, 0x00, 0x00, 0x00, 0x00,
];

/// Maximum value whose square fits in native field
// 170141183460469231731687303715884105728
// BigEndian -> 80000000 00000000 00000000 00000000
static PALLAS_SQR: &[u8] = &[
    0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// The zero byte
static ZERO: &[u8] = &[0x00];

/// The one byte
static ONE: &[u8] = &[0x01];

fn ffmul_test(
    full: bool,
    left_input: &[u8],
    right_input: &[u8],
    foreign_modulus: &[u8],
) -> (
    ForeignElement<PallasField, 3>,
    ForeignElement<PallasField, 3>,
    ForeignElement<PallasField, 3>,
    [Vec<PallasField>; COLUMNS],
) {
    // Create gates
    let (mut next_row, mut gates) = CircuitGate::<Fp>::create_foreign_field_mul(0);
    for _ in 0..(1 << 13) {
        // Temporary workaround for lookup-table/domain-size issue
        gates.push(CircuitGate::zero(Wire::new(next_row)));
        next_row += 1;
    }

    // Create operands and modulus
    let left_input = ForeignElement::<PallasField, 3>::from_be(left_input);
    let right_input = ForeignElement::<PallasField, 3>::from_be(right_input);
    let foreign_modulus = ForeignElement::<PallasField, 3>::from_be(foreign_modulus);

    // Compute witness
    let witness = foreign_field_mul::witness::create(
        left_input.clone(),
        right_input.clone(),
        foreign_modulus.clone(),
    );

    let runner = if full {
        // Create prover index with test framework
        Some(
            TestFramework::default()
                .gates(gates.clone())
                .witness(witness.clone())
                .lookup_tables(vec![foreign_field_mul::gadget::lookup_table()])
                .foreign_modulus(Some(foreign_modulus.to_biguint()))
                .setup(),
        )
    } else {
        None
    };

    let cs = if let Some(runner) = runner {
        runner.prover_index().cs.clone()
    } else {
        // If not full mode, just create constraint system (this is much faster)
        ConstraintSystem::create(gates.clone())
            .foreign_field_modulus(&Some(foreign_modulus.to_biguint()))
            .build()
            .unwrap()
    };

    // Perform witness verification (quick checks)
    for row in 0..witness[0].len() {
        assert_eq!(
            gates[row].verify_witness::<Vesta>(
                row,
                &witness,
                &cs,
                &witness[0][0..cs.public].to_vec()
            ),
            Ok(())
        );
    }

    if full {
        // Temporary way to test until working with prove_and_verify
        for row in 20..=witness[0].len() {
            // Last two rows are ffmul gates
            assert_eq!(
                cs.gates[row].verify::<Vesta>(row, &witness, &cs, &[]),
                Ok(())
            );
        }

        // TODO: Switch this
        // runner.prove_and_verify();
    }

    (left_input, right_input, foreign_modulus, witness)
}

#[test]
// Multiply zeroes. This checks that small amounts also get packed into limbs
fn test_zero_mul() {
    let (_, _, _, witness) = ffmul_test(true, ZERO, ZERO, SECP256K1_MOD);

    // Check quotient and remainder values are zero
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
    let (left_input, _, _, witness) = ffmul_test(true, SECP256K1_MAX, ONE, SECP256K1_MOD);

    // Check quotient is zero and remainder is SECP256K1_MAX
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
    let (left_input, _, _, witness) = ffmul_test(true, PALLAS_SQR, PALLAS_SQR, SECP256K1_MOD);

    // Check quotient is zero and remainder is the square
    let multiplicand = left_input.to_biguint();
    let square = multiplicand.pow(2u32);
    let product = ForeignElement::<PallasField, 3>::from_biguint(square);
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
    let (left_input, _, _, witness) = ffmul_test(true, SECP256K1_SQR, SECP256K1_SQR, SECP256K1_MOD);

    // Check quotient is zero and remainder is the square
    let multiplicand = left_input.to_biguint();
    let square = multiplicand.pow(2u32);
    let product = ForeignElement::<PallasField, 3>::from_biguint(square);
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
    // let (_, _, _, _) =  ffmul_test(false, _PALLAS_MAX, _PALLAS_MAX, SECP256K1_MOD);
    // // fails zer
}

#[test]
// Test squaring of the maximum foreign field values
// ( f - 1) * (f - 1) = f^2 - 2f + 1 = f * (f - 2) + 1
fn test_max_foreign_multiplicands() {
    let (_, _, _, _) = ffmul_test(true, SECP256K1_MAX, SECP256K1_MAX, SECP256K1_MOD);
}
