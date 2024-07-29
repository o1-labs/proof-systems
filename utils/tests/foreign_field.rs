use ark_ec::AffineRepr;
use mina_curves::pasta::Pallas as CurvePoint;
use num_bigint::{BigUint, RandBigInt};
use num_traits::One;
use o1_utils::{field_helpers::FieldHelpers, foreign_field::*};

/// Base field element type
pub type BaseField = <CurvePoint as AffineRepr>::BaseField;

fn secp256k1_modulus() -> BigUint {
    BigUint::from_bytes_be(&secp256k1::constants::FIELD_SIZE)
}

#[test]
fn test_big_be() {
    let big = secp256k1_modulus();
    let bytes = big.to_bytes_be();
    assert_eq!(
        ForeignElement::<BaseField, 3>::from_be(&bytes),
        ForeignElement::<BaseField, 3>::from_biguint(big)
    );
}

#[test]
fn test_to_biguint() {
    let big = secp256k1_modulus();
    let bytes = big.to_bytes_be();
    let fe = ForeignElement::<BaseField, 3>::from_be(&bytes);
    assert_eq!(fe.to_biguint(), big);
}

#[test]
fn test_from_biguint() {
    let one = ForeignElement::<BaseField, 3>::from_be(&[0x01]);
    assert_eq!(
        BaseField::from_biguint(&one.to_biguint()).unwrap(),
        BaseField::one()
    );

    let max_big = BaseField::modulus_biguint() - 1u32;
    let max_fe = ForeignElement::<BaseField, 3>::from_biguint(max_big.clone());
    assert_eq!(
        BaseField::from_biguint(&max_fe.to_biguint()).unwrap(),
        BaseField::from_bytes(&max_big.to_bytes_le()).unwrap(),
    );
}

#[test]
fn test_negate_modulus_safe1() {
    secp256k1_modulus().negate();
}

#[test]
fn test_negate_modulus_safe2() {
    BigUint::binary_modulus().sqrt().negate();
}

#[test]
fn test_negate_modulus_safe3() {
    (BigUint::binary_modulus() / BigUint::from(2u32)).negate();
}

#[test]
#[should_panic]
fn test_negate_modulus_unsafe1() {
    (BigUint::binary_modulus() - BigUint::one()).negate();
}

#[test]
#[should_panic]
fn test_negate_modulus_unsafe2() {
    (BigUint::binary_modulus() + BigUint::one()).negate();
}

#[test]
#[should_panic]
fn test_negate_modulus_unsafe3() {
    BigUint::binary_modulus().negate();
}

#[test]
fn check_negation() {
    let rng = &mut o1_utils::tests::make_test_rng(None);
    for _ in 0..10 {
        rng.gen_biguint(256).negate();
    }
}

#[test]
fn check_good_limbs() {
    let rng = &mut o1_utils::tests::make_test_rng(None);
    for _ in 0..100 {
        let x = rng.gen_biguint(264);
        assert_eq!(x.to_limbs().len(), 3);
        assert_eq!(x.to_limbs().compose(), x);
        assert_eq!(x.to_compact_limbs().len(), 2);
        assert_eq!(x.to_compact_limbs().compose(), x);
        assert_eq!(x.to_compact_limbs().compose(), x.to_limbs().compose());

        assert_eq!(x.to_field_limbs::<BaseField>().len(), 3);
        assert_eq!(x.to_field_limbs::<BaseField>().compose(), x);
        assert_eq!(x.to_compact_field_limbs::<BaseField>().len(), 2);
        assert_eq!(x.to_compact_field_limbs::<BaseField>().compose(), x);
        assert_eq!(
            x.to_compact_field_limbs::<BaseField>().compose(),
            x.to_field_limbs::<BaseField>().compose()
        );

        assert_eq!(x.to_limbs().to_fields::<BaseField>(), x.to_field_limbs());
        assert_eq!(x.to_field_limbs::<BaseField>().to_biguints(), x.to_limbs());
    }
}

#[test]
#[should_panic]
fn check_bad_limbs_1() {
    let rng = &mut o1_utils::tests::make_test_rng(None);
    assert_ne!(rng.gen_biguint(265).to_limbs().len(), 3);
}

#[test]
#[should_panic]
fn check_bad_limbs_2() {
    let rng = &mut o1_utils::tests::make_test_rng(None);
    assert_ne!(rng.gen_biguint(265).to_compact_limbs().len(), 2);
}

#[test]
#[should_panic]
fn check_bad_limbs_3() {
    let rng = &mut o1_utils::tests::make_test_rng(None);
    assert_ne!(rng.gen_biguint(265).to_field_limbs::<BaseField>().len(), 3);
}

#[test]
#[should_panic]
fn check_bad_limbs_4() {
    let rng = &mut o1_utils::tests::make_test_rng(None);
    assert_ne!(
        rng.gen_biguint(265)
            .to_compact_field_limbs::<BaseField>()
            .len(),
        2
    );
}
