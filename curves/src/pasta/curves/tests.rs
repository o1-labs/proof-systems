use std::str::FromStr;

use crate::pasta::{Fp, Pallas};
use ark_algebra_test_templates::{curves::*, groups::*};
use ark_ec::AffineCurve;
use ark_std::test_rng;
use num_bigint::BigUint;
use rand::Rng;

use super::pallas;

#[test]
fn test_pallas_projective_curve() {
    curve_tests::<pallas::ProjectivePallas>();

    sw_tests::<pallas::PallasParameters>();
}

#[test]
fn test_pallas_projective_group() {
    let mut rng = test_rng();
    let a: pallas::ProjectivePallas = rng.gen();
    let b: pallas::ProjectivePallas = rng.gen();
    group_test(a, b);
}

#[test]
fn test_pallas_generator() {
    let generator = pallas::Pallas::prime_subgroup_generator();
    assert!(generator.is_on_curve());
    assert!(generator.is_in_correct_subgroup_assuming_on_curve());
}

#[test]
fn test_regression_vesta_biguint_into_returns_canonical_representation() {
    // This regression test is to ensure that the BigUint::into() impl for Vesta
    // returns the canonical representation of the field element and not the
    // montgomery representation.
    // Commit: 0863042ca383c6578564e166724e9dbc66da19bf
    let p_x = Fp::from_str("1").unwrap();
    let p_y = Fp::from_str(
        "12418654782883325593414442427049395787963493412651469444558597405572177144507",
    )
    .unwrap();
    let p1 = Pallas::new(p_x, p_y, false);
    let p_x_biguint: BigUint = p1.x.into();
    let p_y_biguint: BigUint = p1.y.into();

    assert_eq!(p_x_biguint, BigUint::from_str("1").unwrap());
    assert_eq!(
        p_y_biguint,
        BigUint::from_str(
            "12418654782883325593414442427049395787963493412651469444558597405572177144507",
        )
        .unwrap()
    );
}

#[test]
fn test_regression_vesta_addition_affine() {
    // This regression test is to ensure that the addition of two points in
    // affine coordinates using the inplace operator `+` works correctly.
    // Commit: 0863042ca383c6578564e166724e9dbc66da19bf
    let p1_x = Fp::from_str("1").unwrap();
    let p1_y = Fp::from_str(
        "12418654782883325593414442427049395787963493412651469444558597405572177144507",
    )
    .unwrap();
    let p1 = Pallas::new(p1_x, p1_y, false);

    let p2_x = Fp::from_str(
        "20444556541222657078399132219657928148671392403212669005631716460534733845831",
    )
    .unwrap();
    let p2_y = Fp::from_str(
        "12418654782883325593414442427049395787963493412651469444558597405572177144507",
    )
    .unwrap();
    let p2 = Pallas::new(p2_x, p2_y, false);

    // The type annotation ensures we have a point with affine coordinates,
    // relying on implicit conversion if the addition outputs a point in a
    // different coordinates set.
    let p3: Pallas = p1 + p2;

    let expected_p3_x = BigUint::from_str(
        "8503465768106391777493614032514048814691664078728891710322960303815233784505",
    )
    .unwrap();
    let expected_p3_y = BigUint::from_str(
        "16529367526445723262478303825122581175399563069290091271396079358777790485830",
    )
    .unwrap();

    let p3_x_biguint: BigUint = p3.x.into();
    let p3_y_biguint: BigUint = p3.y.into();
    assert_eq!(expected_p3_x, p3_x_biguint);
    assert_eq!(expected_p3_y, p3_y_biguint);
}
