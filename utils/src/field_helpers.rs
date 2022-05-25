use ark_ff::{BigInteger, Field, FpParameters, PrimeField};
use num_bigint::BigUint;
use std::ops::Neg;
use thiserror::Error;

// Field helpers error
#[derive(Error, Debug, Clone, Copy, PartialEq)]
pub enum FieldHelpersError {
    #[error("failed to deserialize field bytes")]
    DeserializeBytes,
    #[error("failed to decode hex")]
    DecodeHex,
}
pub type Result<T> = std::result::Result<T, FieldHelpersError>;

/// Field element helpers
pub trait FieldHelpers<F> {
    /// Deserialize from bytes
    fn from_bytes(bytes: &[u8]) -> Result<F>;

    /// Deserialize from hex
    fn from_hex(hex: &str) -> Result<F>;

    /// Deserialize from bits
    fn from_bits(bits: &[bool]) -> Result<F>;

    /// Serialize to bytes
    fn to_bytes(self) -> Vec<u8>;

    /// Serialize to hex
    fn to_hex(self) -> String;

    /// Serialize to bits
    fn to_bits(self) -> Vec<bool>;

    /// Field size in bytes
    fn size_in_bytes() -> usize
    where
        F: PrimeField,
    {
        F::size_in_bits() / 8 + (F::size_in_bits() % 8 != 0) as usize
    }

    /// Get the modulus as `BigUint`
    fn modulus_biguint() -> BigUint
    where
        F: PrimeField,
    {
        BigUint::from_bytes_le(&F::Params::MODULUS.to_bytes_le())
    }
}

impl<F: Field> FieldHelpers<F> for F {
    fn from_bytes(bytes: &[u8]) -> Result<F> {
        F::deserialize(&mut &*bytes).map_err(|_| FieldHelpersError::DeserializeBytes)
    }

    fn from_hex(hex: &str) -> Result<F> {
        let bytes: Vec<u8> = hex::decode(hex).map_err(|_| FieldHelpersError::DecodeHex)?;
        F::deserialize(&mut &bytes[..]).map_err(|_| FieldHelpersError::DeserializeBytes)
    }

    fn from_bits(bits: &[bool]) -> Result<F> {
        let bytes = bits
            .iter()
            .enumerate()
            .fold(F::zero().to_bytes(), |mut bytes, (i, bit)| {
                bytes[i / 8] |= (*bit as u8) << (i % 8);
                bytes
            });

        F::deserialize(&mut &bytes[..]).map_err(|_| FieldHelpersError::DeserializeBytes)
    }

    fn to_bytes(self) -> Vec<u8> {
        let mut bytes: Vec<u8> = vec![];
        self.serialize(&mut bytes)
            .expect("Failed to serialize field");

        bytes
    }

    fn to_hex(self) -> String {
        hex::encode(self.to_bytes())
    }

    fn to_bits(self) -> Vec<bool> {
        self.to_bytes().iter().fold(vec![], |mut bits, byte| {
            let mut byte = *byte;
            for _ in 0..8 {
                bits.push(byte & 0x01 == 0x01);
                byte >>= 1;
            }
            bits
        })
    }
}

pub fn i32_to_field<F: From<u64> + Neg<Output = F>>(i: i32) -> F {
    if i >= 0 {
        F::from(i as u64)
    } else {
        -F::from(-i as u64)
    }
}

#[cfg(test)]
mod tests {
    use ark_ec::AffineCurve;
    use ark_ff::{One, PrimeField};
    use mina_curves::pasta::pallas;

    // Affine curve point type
    pub use pallas::Affine as CurvePoint;
    // Base field element type
    pub type BaseField = <CurvePoint as AffineCurve>::BaseField;

    use super::*;

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
            BaseField::from_hex(
                "0f5314f176fddb5d769b7de2027469d027ad428fadcf0c02396e6280142efb7d8"
            ),
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

        assert_eq!(
            BaseField::from_hex("25b89cf1a14e2de6124fea18758bf890af76fff31b7fc68713c7653c61b49d39")
                .is_ok(),
            true
        );

        let field_hex = "f2eee8d8f6e5fb182c610cae6c5393fce69dc4d900e7b4923b074e54ad00fb36";
        assert_eq!(
            BaseField::to_hex(
                BaseField::from_hex(field_hex).expect("Failed to deserialize field hex")
            ),
            field_hex
        );
    }

    #[test]
    fn field_bytes() {
        assert_eq!(
            BaseField::from_bytes(&[
                46, 174, 218, 228, 42, 116, 97, 213, 149, 45, 39, 185, 126, 202, 208, 104, 182,
                152, 235, 185, 78, 138, 14, 76, 69, 56, 139, 182, 19, 222, 126, 8
            ])
            .is_ok(),
            true
        );

        assert_eq!(
            BaseField::from_bytes(&[46, 174, 218, 228, 42, 116, 97, 213]),
            Err(FieldHelpersError::DeserializeBytes)
        );

        assert_eq!(
            BaseField::to_hex(
                BaseField::from_bytes(&[
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
        assert_eq!(lifetime_test().is_ok(), true);
    }

    #[test]
    fn field_bits() {
        let fe =
            BaseField::from_hex("2cc3342ad3cd516175b8f0d0189bc3bdcb7947a4cc96c7cfc8d5df10cc443832")
                .expect("Failed to deserialize field hex");

        let fe_check =
            BaseField::from_bits(&fe.to_bits()).expect("Failed to deserialize field bits");
        assert_eq!(fe, fe_check);

        assert_eq!(
            BaseField::from_bits(
                &BaseField::from_hex(
                    "e9a8f3b489990ed7eddce497b7138c6a06ff802d1b58fca1997c5f2ee971cd32"
                )
                .expect("Failed to deserialize field hex")
                .to_bits()
            )
            .is_ok(),
            true
        );

        assert_eq!(
            BaseField::from_bits(&vec![true; BaseField::size_in_bits()]),
            Err(FieldHelpersError::DeserializeBytes)
        );

        assert_eq!(
            BaseField::from_bits(&[false, true, false, true]).is_ok(),
            true
        );

        assert_eq!(
            BaseField::from_bits(&[true, false, false]).expect("Failed to deserialize field bytes"),
            BaseField::one()
        );
    }
}
