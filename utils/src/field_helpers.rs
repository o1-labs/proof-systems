//! Useful helper methods to extend [ark_ff::Field].

use ark_ff::{BigInteger, Field, FpParameters, PrimeField};
use num_bigint::{BigInt, BigUint, RandBigInt, ToBigInt};
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

    /// Serialize field element f to a (positive) BigInt directly.
    fn to_bigint_positive(&self) -> BigInt
    where
        F: PrimeField,
    {
        Self::to_biguint(self).to_bigint().unwrap()
    }

    /// Create a new field element from this field elements bits
    fn bits_to_field(&self, start: usize, end: usize) -> Result<F>;

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

    /// Creates a field element from bits (little endian)
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

    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = vec![];
        self.serialize(&mut bytes)
            .expect("Failed to serialize field");

        bytes
    }

    fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }

    /// Converts a field element into bit representation (little endian)
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
