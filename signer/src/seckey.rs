//! Secret key structures and helpers

use crate::ScalarField;
use ark_ff::UniformRand;
use o1_utils::FieldHelpers;
use rand::{self, CryptoRng, RngCore};
use thiserror::Error;

/// Keypair error
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum SecKeyError {
    /// Invalid secret key hex
    #[error("invalid secret key hex")]
    SecretKeyHex,
    /// Invalid secret key bytes
    #[error("Invalid secret key bytes")]
    SecretKeyBytes,
}
/// Keypair result
pub type Result<T> = std::result::Result<T, SecKeyError>;

/// Secret key
#[derive(Clone, Debug, PartialEq, Eq)] // No Debug nor Display
pub struct SecKey(ScalarField);

impl SecKey {
    /// Generate a random secret key
    pub fn rand(rng: &mut (impl RngCore + CryptoRng)) -> Self {
        let secret: ScalarField = ScalarField::rand(rng);

        Self(secret)
    }

    /// Create secret key from scalar field element
    pub fn new(scalar: ScalarField) -> Self {
        Self(scalar)
    }

    /// Deserialize secret key from bytes
    ///
    /// # Errors
    ///
    /// Will give error if `bytes` do not match certain requirements.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != ScalarField::size_in_bytes() {
            return Err(SecKeyError::SecretKeyBytes);
        }
        let mut sec_bytes = vec![0u8; ScalarField::size_in_bytes()];
        sec_bytes.clone_from_slice(bytes);
        sec_bytes.reverse(); // mina scalars hex format is in big-endian order
        let secret =
            ScalarField::from_bytes(&sec_bytes).map_err(|_| SecKeyError::SecretKeyBytes)?;
        Ok(SecKey(secret))
    }

    /// Deserialize secret key from hex
    ///
    /// # Errors
    ///
    /// Will give error if `hex` string does not match certain requirements.
    pub fn from_hex(secret_hex: &str) -> Result<Self> {
        let bytes: Vec<u8> = hex::decode(secret_hex).map_err(|_| SecKeyError::SecretKeyHex)?;
        SecKey::from_bytes(&bytes)
    }

    /// Borrows secret key as scalar field element
    pub fn scalar(&self) -> &ScalarField {
        &self.0
    }

    /// Convert secret key into scalar field element
    pub fn into_scalar(self) -> ScalarField {
        self.0
    }

    /// Deserialize secret key into bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = self.0.to_bytes();
        bytes.reverse(); // mina scalars hex format is in big-endian order
        bytes
    }

    /// Deserialize secret key into hex
    pub fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_hex() {
        assert_eq!(
            SecKey::to_hex(
                &SecKey::from_hex(
                    "3d12f41e24f105366b609aa23a4ef28cbae919239177275ea27bd0cabd1debd1"
                )
                .expect("failed to decode sec key"),
            ),
            "3d12f41e24f105366b609aa23a4ef28cbae919239177275ea27bd0cabd1debd1"
        );

        assert_eq!(
            SecKey::to_hex(
                &SecKey::from_hex(
                    "285f2e2a534a9ff25971875538ea346038974ef137a069a4892f50e60910f7d8"
                )
                .expect("failed to decode sec key"),
            ),
            "285f2e2a534a9ff25971875538ea346038974ef137a069a4892f50e60910f7d8"
        );

        assert_eq!(
            SecKey::from_hex("d8f71009e6502f89a469a037f14e97386034ea3855877159f29f4a532a2e5f28"),
            Err(SecKeyError::SecretKeyBytes)
        );

        assert_eq!(
            SecKey::from_hex("d8f71009g6502f89a469a037f14e97386034ea3855877159f29f4a532a2e5f28"),
            Err(SecKeyError::SecretKeyHex)
        );
    }

    #[test]
    fn to_bytes() {
        let bytes = [
            40, 95, 46, 42, 83, 74, 159, 242, 89, 113, 135, 85, 56, 234, 52, 96, 56, 151, 78, 241,
            55, 160, 105, 164, 137, 47, 80, 230, 9, 16, 247, 216,
        ];
        assert_eq!(
            SecKey::from_bytes(&bytes)
                .expect("failed to decode sec key")
                .to_bytes(),
            bytes
        );

        // negative test (too many bytes)
        assert_eq!(
            SecKey::from_bytes(&[
                40, 95, 46, 42, 83, 74, 159, 242, 89, 113, 135, 85, 56, 234, 52, 96, 56, 151, 78,
                241, 55, 160, 105, 164, 137, 47, 80, 230, 9, 16, 247, 216, 10
            ]),
            Err(SecKeyError::SecretKeyBytes)
        );

        // negative test (too few bytes)
        assert_eq!(
            SecKey::from_bytes(&[
                40, 95, 46, 42, 83, 74, 159, 242, 89, 113, 135, 85, 56, 234, 52, 96, 56, 151, 78,
                241, 55, 160, 105, 164, 137, 47, 80, 230, 9, 16, 247
            ]),
            Err(SecKeyError::SecretKeyBytes)
        );
    }
}
