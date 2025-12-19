//! Secret key structures and helpers

#[cfg(feature = "no-std")]
extern crate alloc;

use crate::ScalarField;
#[cfg(feature = "no-std")]
use alloc::{string::String, vec, vec::Vec};
use ark_ff::UniformRand;
use o1_utils::FieldHelpers;
use rand::{self, CryptoRng, RngCore};
use sha2::{Digest, Sha256};
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
    /// Invalid secrey key length
    #[error("Invalid secret key length")]
    SecretKeyLength,
    /// Invalid base58 secret key
    #[error("Invalid secret key base58")]
    SecretKeyBase58,
    /// Invalid secret key checksum
    #[error("Invalid secret key checksum")]
    SecretKeyChecksum,
    /// Invalid secret key version
    #[error("Invalid secret key version")]
    SecretKeyVersion,
}
/// Keypair result
pub type Result<T> = core::result::Result<T, SecKeyError>;

/// Secret key length
pub const MINA_SEC_KEY_LEN: usize = 52;

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

    /// Deserialize base58 encoded secret key
    ///
    /// # Errors
    ///
    /// Will give error if `base58` string does not match certain requirements.
    pub fn from_base58(base58: &str) -> Result<Self> {
        if base58.len() != MINA_SEC_KEY_LEN {
            return Err(SecKeyError::SecretKeyLength);
        }

        let bytes = bs58::decode(base58)
            .into_vec()
            .map_err(|_| SecKeyError::SecretKeyBase58)?;

        let (raw, checksum) = (&bytes[..bytes.len() - 4], &bytes[bytes.len() - 4..]);

        let hash = Sha256::digest(&Sha256::digest(raw)[..]);

        if checksum != &hash[..4] {
            return Err(SecKeyError::SecretKeyChecksum);
        }

        let (version, scalar_bytes) = (&raw[..2], &raw[2..raw.len()]);

        if version != [0x5a, 0x01] {
            return Err(SecKeyError::SecretKeyVersion);
        }

        let mut scalar_bytes = scalar_bytes.to_vec();

        scalar_bytes.reverse();

        Self::from_bytes(&scalar_bytes)
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

    /// Deserialize secret key into base58
    pub fn to_base58(&self) -> String {
        let mut raw: Vec<u8> = vec![0x5a, 0x01];

        let mut scalar_bytes = self.to_bytes();
        scalar_bytes.reverse();

        raw.extend(scalar_bytes);

        let checksum = Sha256::digest(&Sha256::digest(&raw[..])[..]);
        raw.extend(&checksum[..4]);

        bs58::encode(raw).into_string()
    }
}
