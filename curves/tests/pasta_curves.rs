use ark_algebra_test_templates::*;
use core::str::FromStr;
use mina_curves::pasta::{Fp, Pallas, ProjectivePallas, ProjectiveVesta};
use num_bigint::BigUint;

test_group!(g1; ProjectivePallas; sw);
test_group!(g2; ProjectiveVesta; sw);

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
    let p1 = Pallas::new_unchecked(p_x, p_y);
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
    let p1 = Pallas::new_unchecked(p1_x, p1_y);

    let p2_x = Fp::from_str(
        "20444556541222657078399132219657928148671392403212669005631716460534733845831",
    )
    .unwrap();
    let p2_y = Fp::from_str(
        "12418654782883325593414442427049395787963493412651469444558597405572177144507",
    )
    .unwrap();
    let p2 = Pallas::new_unchecked(p2_x, p2_y);

    // The type annotation ensures we have a point with affine coordinates,
    // relying on implicit conversion if the addition outputs a point in a
    // different coordinates set.
    let p3: Pallas = (p1 + p2).into();

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
