//! Keypair structures and algorithms
//!
//! Definition of secret key, keypairs and related helpers

extern crate alloc;

use crate::{pubkey::PubKeyError, seckey::SecKeyError, CurvePoint, PubKey, ScalarField, SecKey};
use alloc::{string::String, vec::Vec};
use core::fmt;
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
#[derive(Clone, PartialEq, Eq)]
pub struct Keypair {
    /// Secret key
    pub secret: SecKey,
    /// Public key
    pub public: PubKey,
}

impl Keypair {
    /// Create keypair from scalar field `secret` element and curve point `public`
    /// Note: Does not check point `public` is on curve
    pub fn from_parts_unsafe(secret: ScalarField, public: CurvePoint) -> Self {
        Self {
            secret: SecKey::new(secret),
            public: PubKey::from_point_unsafe(public),
        }
    }

    /// Create keypair from secret key
    pub fn from_secret_key(secret_key: SecKey) -> Result<Self> {
        let public = PubKey::from_secret_key(secret_key.clone())?;

        // Safe now because PubKey::from_secret_key() checked point is on the curve
        Ok(Self::from_parts_unsafe(
            secret_key.into_scalar(),
            public.into_point(),
        ))
    }

    /// Generate random keypair
    pub fn rand(rng: &mut (impl RngCore + CryptoRng)) -> Result<Self> {
        let sec_key: SecKey = SecKey::rand(rng);
        Keypair::from_secret_key(sec_key)
    }

    /// Deserialize keypair from secret key bytes
    ///
    /// # Errors
    ///
    /// Will give error if `bytes` do not match certain requirements.
    pub fn from_bytes(secret_bytes: &[u8]) -> Result<Self> {
        let secret = SecKey::from_bytes(secret_bytes)?;
        Keypair::from_secret_key(secret)
    }

    /// Deserialize keypair from secret key hex
    ///
    /// # Errors
    ///
    /// Will give error if `hex` string does not match certain requirements.
    pub fn from_hex(secret_hex: &str) -> Result<Self> {
        let secret = SecKey::from_hex(secret_hex)?;
        Keypair::from_secret_key(secret)
    }

    /// Obtain the Mina address corresponding to the keypair's public key
    pub fn get_address(self) -> String {
        self.public.into_address()
    }

    /// Deserialize keypair into bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        self.secret.to_bytes()
    }

    /// Deserialize keypair into hex
    pub fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
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
