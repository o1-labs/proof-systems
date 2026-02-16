use ark_ec::AffineRepr;
use ark_ff::One;
use mina_curves::pasta::Pallas as CurvePoint;
use num_bigint::BigUint;
use o1_utils::{field_helpers::FieldHelpers, ForeignElement};

/// Base field element type
pub type BaseField = <CurvePoint as AffineRepr>::BaseField;

fn secp256k1_modulus() -> BigUint {
    BigUint::from_bytes_be(&secp256k1::constants::FIELD_SIZE)
}

const TEST_B_1: usize = 88;
const TEST_N_1: usize = 3;
const TEST_B_2: usize = 15;
const TEST_N_2: usize = 18;

#[test]
fn test_big_be() {
    let big = secp256k1_modulus();
    let bytes = big.to_bytes_be();
    assert_eq!(
        ForeignElement::<BaseField, TEST_B_1, 3>::from_be(&bytes),
        ForeignElement::<BaseField, TEST_B_1, 3>::from_biguint(&big)
    );
    assert_eq!(
        ForeignElement::<BaseField, TEST_B_2, TEST_N_2>::from_be(&bytes),
        ForeignElement::<BaseField, TEST_B_2, TEST_N_2>::from_biguint(&big)
    );
}

#[test]
fn test_to_biguint() {
    let big = secp256k1_modulus();
    let bytes = big.to_bytes_be();
    let fe = ForeignElement::<BaseField, TEST_B_1, TEST_N_1>::from_be(&bytes);
    assert_eq!(fe.to_biguint(), big);
    let fe2 = ForeignElement::<BaseField, TEST_B_2, TEST_N_2>::from_be(&bytes);
    assert_eq!(fe2.to_biguint(), big);
}

#[test]
fn test_from_biguint() {
    {
        let one = ForeignElement::<BaseField, TEST_B_1, TEST_N_1>::from_be(&[0x01]);
        assert_eq!(
            BaseField::from_biguint(&one.to_biguint()).unwrap(),
            BaseField::one()
        );

        let max_big = BaseField::modulus_biguint() - 1u32;
        let max_fe = ForeignElement::<BaseField, TEST_B_1, TEST_N_1>::from_biguint(&max_big);
        assert_eq!(
            BaseField::from_biguint(&max_fe.to_biguint()).unwrap(),
            BaseField::from_bytes(&max_big.to_bytes_le()).unwrap(),
        );
    }
    {
        let one = ForeignElement::<BaseField, TEST_B_2, TEST_N_2>::from_be(&[0x01]);
        assert_eq!(
            BaseField::from_biguint(&one.to_biguint()).unwrap(),
            BaseField::one()
        );

        let max_big = BaseField::modulus_biguint() - 1u32;
        let max_fe = ForeignElement::<BaseField, TEST_B_2, TEST_N_2>::from_biguint(&max_big);
        assert_eq!(
            BaseField::from_biguint(&max_fe.to_biguint()).unwrap(),
            BaseField::from_bytes(&max_big.to_bytes_le()).unwrap(),
        );
    }
}
