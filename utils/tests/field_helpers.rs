use ark_ec::AffineRepr;
use ark_ff::{BigInteger, One, PrimeField};
use mina_curves::pasta::Pallas as CurvePoint;
use num_bigint::BigUint;
use o1_utils::{
    field_helpers::{FieldHelpersError, Result},
    BigUintFieldHelpers, FieldHelpers,
};

/// Base field element type
pub type BaseField = <CurvePoint as AffineRepr>::BaseField;

#[test]
fn field_hex() {
    assert_eq!(
        BaseField::from_hex(""),
        Err(FieldHelpersError::DeserializeBytes)
    );
    assert_eq!(
        BaseField::from_hex("1428fadcf0c02396e620f14f176fddb5d769b7de2027469d027a80142ef8f07"),
        Err(FieldHelpersError::DecodeHex)
    );
    assert_eq!(
        BaseField::from_hex("0f5314f176fddb5d769b7de2027469d027ad428fadcf0c02396e6280142efb7d8"),
        Err(FieldHelpersError::DecodeHex)
    );
    assert_eq!(
        BaseField::from_hex("g64244176fddb5d769b7de2027469d027ad428fadcf0c02396e6280142efb7d8"),
        Err(FieldHelpersError::DecodeHex)
    );
    assert_eq!(
        BaseField::from_hex("0cdaf334e9632268a5aa959c2781fb32bf45565fe244ae42c849d3fdc7c644fd"),
        Err(FieldHelpersError::DeserializeBytes)
    );

    assert!(BaseField::from_hex(
        "25b89cf1a14e2de6124fea18758bf890af76fff31b7fc68713c7653c61b49d39"
    )
    .is_ok());

    let field_hex = "f2eee8d8f6e5fb182c610cae6c5393fce69dc4d900e7b4923b074e54ad00fb36";
    assert_eq!(
        BaseField::to_hex(
            &BaseField::from_hex(field_hex).expect("Failed to deserialize field hex")
        ),
        field_hex
    );
}

#[test]
fn field_bytes() {
    assert!(BaseField::from_bytes(&[
        46, 174, 218, 228, 42, 116, 97, 213, 149, 45, 39, 185, 126, 202, 208, 104, 182, 152, 235,
        185, 78, 138, 14, 76, 69, 56, 139, 182, 19, 222, 126, 8
    ])
    .is_ok(),);

    assert_eq!(
        BaseField::from_bytes(&[46, 174, 218, 228, 42, 116, 97, 213]),
        Err(FieldHelpersError::DeserializeBytes)
    );

    assert_eq!(
        BaseField::to_hex(
            &BaseField::from_bytes(&[
                46, 174, 218, 228, 42, 116, 97, 213, 149, 45, 39, 185, 126, 202, 208, 104, 182,
                152, 235, 185, 78, 138, 14, 76, 69, 56, 139, 182, 19, 222, 126, 8
            ])
            .expect("Failed to deserialize field bytes")
        ),
        "2eaedae42a7461d5952d27b97ecad068b698ebb94e8a0e4c45388bb613de7e08"
    );

    fn lifetime_test() -> Result<BaseField> {
        let bytes = [0; 32];
        BaseField::from_bytes(&bytes)
    }
    assert!(lifetime_test().is_ok());
}

#[test]
fn field_bits() {
    let fe =
        BaseField::from_hex("2cc3342ad3cd516175b8f0d0189bc3bdcb7947a4cc96c7cfc8d5df10cc443832")
            .expect("Failed to deserialize field hex");

    let fe_check = BaseField::from_bits(&fe.to_bits()).expect("Failed to deserialize field bits");
    assert_eq!(fe, fe_check);

    assert!(BaseField::from_bits(
        &BaseField::from_hex("e9a8f3b489990ed7eddce497b7138c6a06ff802d1b58fca1997c5f2ee971cd32")
            .expect("Failed to deserialize field hex")
            .to_bits()
    )
    .is_ok());

    assert_eq!(
        BaseField::from_bits(&vec![
            true;
            <BaseField as PrimeField>::MODULUS_BIT_SIZE as usize
        ]),
        Err(FieldHelpersError::DeserializeBytes)
    );

    assert!(BaseField::from_bits(&[false, true, false, true]).is_ok(),);

    assert_eq!(
        BaseField::from_bits(&[true, false, false]).expect("Failed to deserialize field bytes"),
        BaseField::one()
    );
}

#[test]
fn field_big() {
    let fe_1024 = BaseField::from(1024u32);
    let big_1024: BigUint = fe_1024.into();
    assert_eq!(big_1024, BigUint::new(vec![1024]));

    assert_eq!(
        BaseField::from_biguint(&big_1024).expect("Failed to deserialize big uint"),
        fe_1024
    );

    let be_zero_32bytes = vec![0x00, 0x00, 0x00, 0x00, 0x00];
    let be_zero_1byte = vec![0x00];
    let big_zero_32 = BigUint::from_bytes_be(&be_zero_32bytes);
    let big_zero_1 = BigUint::from_bytes_be(&be_zero_1byte);
    let field_zero = BaseField::from(0u32);

    assert_eq!(
        BigUint::from_bytes_be(&field_zero.into_bigint().to_bytes_be()),
        BigUint::from_bytes_be(&be_zero_32bytes)
    );

    assert_eq!(
        BaseField::from_biguint(&BigUint::from_bytes_be(&be_zero_32bytes))
            .expect("Failed to convert big uint"),
        field_zero
    );

    assert_eq!(big_zero_32, big_zero_1);

    assert_eq!(
        BaseField::from_biguint(&big_zero_32).expect("Failed"),
        BaseField::from_biguint(&big_zero_1).expect("Failed")
    );

    let bytes = [
        46, 174, 218, 228, 42, 116, 97, 213, 149, 45, 39, 185, 126, 202, 208, 104, 182, 152, 235,
        185, 78, 138, 14, 76, 69, 56, 139, 182, 19, 222, 126, 8,
    ];
    let fe = BaseField::from_bytes(&bytes).expect("failed to create field element from bytes");
    let bi = BigUint::from_bytes_le(&bytes);
    assert_eq!(fe.to_biguint(), bi);
    assert_eq!(bi.to_field::<BaseField>().unwrap(), fe);
}
