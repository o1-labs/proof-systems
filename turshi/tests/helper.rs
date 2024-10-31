use ark_ec::AffineRepr;
use mina_curves::pasta::Pallas as CurvePoint;
use o1_utils::FieldHelpers;
use turshi::helper::*;

/// Base field element type
pub type BaseField = <CurvePoint as AffineRepr>::BaseField;

#[test]
fn test_field_to_bits() {
    let fe = BaseField::from(256u32);
    let bits = fe.to_bits();
    println!("{:?}", &bits[0..16]);
}

#[test]
fn test_field_to_chunks() {
    let fe = BaseField::from(0x480680017fff8000u64);
    let chunk = fe.u16_chunk(1);
    assert_eq!(chunk, BaseField::from(0x7fff));
}

#[test]
fn test_hex_and_u64() {
    let fe = BaseField::from(0x480680017fff8000u64);
    let change = BaseField::from_hex(&fe.to_hex()).unwrap();
    assert_eq!(fe, change);
    let word = change.to_u64();
    assert_eq!(word, 0x480680017fff8000u64);
}
