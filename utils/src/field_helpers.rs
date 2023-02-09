//! Useful helper methods to extend [ark_ff::Field].

use ark_ff::{BigInteger, Field, PrimeField};
use num_bigint::{BigUint, RandBigInt};
use rand::rngs::StdRng;
use std::ops::Neg;
use thiserror::Error;

/// Field helpers error
#[allow(missing_docs)]
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum FieldHelpersError {
    #[error("failed to deserialize field bytes")]
    DeserializeBytes,
    #[error("failed to deserialize field bits")]
    DeserializeBits,
    #[error("failed to decode hex")]
    DecodeHex,
    #[error("failed to convert BigUint into field element")]
    FromBigToField,
}

/// Result alias using [FieldHelpersError]
pub type Result<T> = std::result::Result<T, FieldHelpersError>;

/// Helper to generate random field elements
pub trait RandomField<F> {
    /// Generates a random field element of up to a given number of bits
    fn gen_field_with_bits(&mut self, bits: usize) -> F;

    /// Initialize a random input with a random value of given length
    fn gen(&mut self, input: Option<F>, bits: Option<usize>) -> F;
}

impl<F: PrimeField> RandomField<F> for StdRng {
    fn gen_field_with_bits(&mut self, bits: usize) -> F {
        F::from_biguint(&self.gen_biguint_below(&BigUint::from(2u8).pow(bits as u32))).unwrap()
    }

    fn gen(&mut self, input: Option<F>, bits: Option<usize>) -> F {
        if let Some(inp) = input {
            inp
        } else {
            assert!(bits.is_some());
            let bits = bits.unwrap();
            self.gen_field_with_bits(bits)
        }
    }
}

/// Helper to obtain two
pub trait Two<F> {
    /// Value two
    fn two() -> F;

    /// Power of two
    fn two_pow(pow: u64) -> F;
}

impl<F: Field> Two<F> for F {
    fn two() -> F {
        F::from(2u8)
    }

    fn two_pow(pow: u64) -> F {
        F::two().pow([pow])
    }
}

/// Field element helpers
///   Unless otherwise stated everything is in little-endian byte order.
pub trait FieldHelpers<F> {
    /// Deserialize from bytes
    fn from_bytes(bytes: &[u8]) -> Result<F>;

    /// Deserialize from little-endian hex
    fn from_hex(hex: &str) -> Result<F>;

    /// Deserialize from bits
    fn from_bits(bits: &[bool]) -> Result<F>;

    /// Deserialize from BigUint
    fn from_biguint(big: &BigUint) -> Result<F>
    where
        F: PrimeField,
    {
        big.clone()
            .try_into()
            .map_err(|_| FieldHelpersError::DeserializeBytes)
    }

    /// Serialize to bytes
    fn to_bytes(&self) -> Vec<u8>;

    /// Serialize to hex
    fn to_hex(&self) -> String;

    /// Serialize to bits
    fn to_bits(&self) -> Vec<bool>;

    /// Serialize field element to a BigUint
    fn to_biguint(&self) -> BigUint
    where
        F: PrimeField,
    {
        BigUint::from_bytes_le(&self.to_bytes())
    }

    /// Create a new field element from this field elements bits
    fn bits_to_field(&self, start: usize, end: usize) -> Result<F>;

    /// Field size in bits
    fn size_in_bits() -> usize
    where
        F: PrimeField,
    {
        F::MODULUS_BIT_SIZE as usize
    }

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
        BigUint::from_bytes_le(&F::MODULUS.to_bytes_le())
    }
}

impl<F: Field> FieldHelpers<F> for F {
    fn from_bytes(bytes: &[u8]) -> Result<F> {
        F::deserialize_compressed(&mut &*bytes).map_err(|_| FieldHelpersError::DeserializeBytes)
    }

    fn from_hex(hex: &str) -> Result<F> {
        let bytes: Vec<u8> = hex::decode(hex).map_err(|_| FieldHelpersError::DecodeHex)?;
        F::deserialize_compressed(&mut &bytes[..]).map_err(|_| FieldHelpersError::DeserializeBytes)
    }

    fn from_bits(bits: &[bool]) -> Result<F> {
        let bytes = bits
            .iter()
            .enumerate()
            .fold(F::zero().to_bytes(), |mut bytes, (i, bit)| {
                bytes[i / 8] |= (*bit as u8) << (i % 8);
                bytes
            });

        F::deserialize_compressed(&mut &bytes[..]).map_err(|_| FieldHelpersError::DeserializeBytes)
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = vec![];
        self.serialize_compressed(&mut bytes)
            .expect("Failed to serialize field");

        bytes
    }

    fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }

    fn to_bits(&self) -> Vec<bool> {
        self.to_bytes().iter().fold(vec![], |mut bits, byte| {
            let mut byte = *byte;
            for _ in 0..8 {
                bits.push(byte & 0x01 == 0x01);
                byte >>= 1;
            }
            bits
        })
    }

    fn bits_to_field(&self, start: usize, end: usize) -> Result<F> {
        F::from_bits(&self.to_bits()[start..end]).map_err(|_| FieldHelpersError::DeserializeBits)
    }
}

/// Field element wrapper for [BigUint]
pub trait BigUintFieldHelpers {
    /// Convert BigUint into PrimeField element
    fn to_field<F: PrimeField>(self) -> Result<F>;
}

impl BigUintFieldHelpers for BigUint {
    fn to_field<F: PrimeField>(self) -> Result<F> {
        F::from_biguint(&self)
    }
}

/// Converts an [i32] into a [Field]
pub fn i32_to_field<F: From<u64> + Neg<Output = F>>(i: i32) -> F {
    if i >= 0 {
        F::from(i as u64)
    } else {
        -F::from(-i as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ec::CurveConfig;

    use ark_ff::One;
    use mina_curves::pasta::pallas::PallasConfig;

    /// Base field element type
    pub type BaseField = <PallasConfig as CurveConfig>::BaseField;

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
            46, 174, 218, 228, 42, 116, 97, 213, 149, 45, 39, 185, 126, 202, 208, 104, 182, 152,
            235, 185, 78, 138, 14, 76, 69, 56, 139, 182, 19, 222, 126, 8
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

        let fe_check =
            BaseField::from_bits(&fe.to_bits()).expect("Failed to deserialize field bits");
        assert_eq!(fe, fe_check);

        assert!(BaseField::from_bits(
            &BaseField::from_hex(
                "e9a8f3b489990ed7eddce497b7138c6a06ff802d1b58fca1997c5f2ee971cd32"
            )
            .expect("Failed to deserialize field hex")
            .to_bits()
        )
        .is_ok());

        assert_eq!(
            BaseField::from_bits(&vec![true; BaseField::size_in_bits()]),
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
            BigUint::from_bytes_be(&field_zero.to_bytes()),
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
            46, 174, 218, 228, 42, 116, 97, 213, 149, 45, 39, 185, 126, 202, 208, 104, 182, 152,
            235, 185, 78, 138, 14, 76, 69, 56, 139, 182, 19, 222, 126, 8,
        ];
        let fe = BaseField::from_bytes(&bytes).expect("failed to create field element from bytes");
        let bi = BigUint::from_bytes_le(&bytes);
        assert_eq!(fe.to_biguint(), bi);
        assert_eq!(bi.to_field::<BaseField>().unwrap(), fe);
    }
}
