//! Keypair structures and algorithms
//!
//! Definition of secret key, keypairs and related helpers

extern crate alloc;

use crate::{pubkey::PubKeyError, seckey::SecKeyError, CurvePoint, PubKey, ScalarField, SecKey};
use alloc::{string::String, vec::Vec};
use core::{convert::TryFrom, fmt};
use rand::{self, CryptoRng, RngCore};
use thiserror::Error;

/// Keypair error
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum KeypairError {
    /// Invalid secret key
    #[error(transparent)]
    SecretKey(#[from] SecKeyError),
    /// Public key error
    #[error(transparent)]
    PublicKey(#[from] PubKeyError),
    /// point not on curve
    #[error("point not on curve")]
    NonCurvePoint,
}
/// Keypair result
pub type Result<T> = core::result::Result<T, KeypairError>;

/// Keypair structure
///
/// The secret key is intentionally private to prevent accidental exposure
/// through logging or serialization. Use [`secret_key()`](Self::secret_key)
/// to access it when needed.
#[derive(Clone, PartialEq, Eq)]
pub struct Keypair {
    /// Secret key (private to prevent accidental exposure)
    secret: SecKey,
    /// Public key
    pub public: PubKey,
}

impl Keypair {
    /// Create keypair from scalar field `secret` element and curve point `public`
    /// Note: Does not check point `public` is on curve
    #[must_use]
    pub const fn from_parts_unsafe(secret: ScalarField, public: CurvePoint) -> Self {
        Self {
            secret: SecKey::new(secret),
            public: PubKey::from_point_unsafe(public),
        }
    }

    /// Returns a reference to the secret key.
    ///
    /// # Security
    ///
    /// Handle the returned secret key with care. Avoid logging, printing,
    /// or transmitting it unless absolutely necessary for cryptographic
    /// operations.
    #[must_use]
    pub const fn secret_key(&self) -> &SecKey {
        &self.secret
    }

    /// Create keypair from secret key
    ///
    /// # Errors
    ///
    /// Returns [`KeypairError`] if the public key cannot be derived from
    /// the secret key. 
    ///
    /// # Deprecated
    ///
    /// Use [`Keypair::try_from`] instead for idiomatic Rust conversions.
    /// This method will be removed in version 0.5.0.
    #[deprecated(
        since = "0.4.0",
        note = "use `Keypair::try_from(secret_key)` instead; will be removed in 0.5.0"
    )]
    pub fn from_secret_key(secret_key: SecKey) -> Result<Self> {
        Self::from_secret_key_impl(secret_key)
    }

    /// Internal implementation of keypair creation from secret key.
    /// Used by both `TryFrom` impl and the deprecated `from_secret_key`.
    fn from_secret_key_impl(secret_key: SecKey) -> Result<Self> {
        let public = PubKey::from_secret_key(&secret_key)?;

        // Safe now because PubKey::from_secret_key() checked point is on the curve
        Ok(Self::from_parts_unsafe(
            secret_key.into_scalar(),
            public.into_point(),
        ))
    }

    /// Generate random keypair
    ///
    /// # Errors
    ///
    /// Returns [`KeypairError`] if the generated secret key produces an
    /// invalid public key.
    pub fn rand(rng: &mut (impl RngCore + CryptoRng)) -> Result<Self> {
        let sec_key: SecKey = SecKey::rand(rng);
        Self::from_secret_key_impl(sec_key)
    }

    /// Deserialize keypair from secret key bytes
    ///
    /// # Errors
    ///
    /// Will give error if `bytes` do not match certain requirements.
    pub fn from_bytes(secret_bytes: &[u8]) -> Result<Self> {
        let secret = SecKey::from_bytes(secret_bytes)?;
        Self::from_secret_key_impl(secret)
    }

    /// Deserialize keypair from secret key hex
    ///
    /// # Errors
    ///
    /// Will give error if `hex` string does not match certain requirements.
    pub fn from_hex(secret_hex: &str) -> Result<Self> {
        let secret = SecKey::from_hex(secret_hex)?;
        Self::from_secret_key_impl(secret)
    }

    /// Obtain the Mina address corresponding to the keypair's public key
    #[must_use]
    pub fn get_address(self) -> String {
        self.public.into_address()
    }

    /// Deserialize keypair into bytes
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.secret.to_bytes()
    }

    /// Deserialize keypair into hex
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }
}

impl TryFrom<SecKey> for Keypair {
    type Error = KeypairError;

    /// Create a keypair from a secret key.
    ///
    /// This is the idiomatic way to convert a [`SecKey`] into a [`Keypair`].
    /// It derives the corresponding public key from the secret key.
    ///
    /// # Errors
    ///
    /// Returns [`KeypairError::PublicKey`] if the secret key is zero or
    /// the derived point is not on the curve.
    ///
    /// # Example
    ///
    /// ```
    /// use std::convert::TryFrom;
    /// use mina_signer::{Keypair, SecKey};
    ///
    /// let secret = SecKey::from_hex(
    ///     "164244176fddb5d769b7de2027469d027ad428fadcc0c02396e6280142efb718"
    /// ).unwrap();
    /// let keypair = Keypair::try_from(secret).unwrap();
    /// ```
    fn try_from(secret_key: SecKey) -> Result<Self> {
        Keypair::from_secret_key_impl(secret_key)
    }
}

impl fmt::Debug for Keypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Omit the secret key for security
        write!(f, "{:?}", self.public)
    }
}

impl fmt::Display for Keypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Omit the secret key for security
        write!(f, "{}", self.public)
    }
}
