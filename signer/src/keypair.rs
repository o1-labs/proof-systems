//! Keypair structures and algorithms
//!
//! Definition of secret key, keypairs and related helpers

use crate::{pubkey::PubKeyError, seckey::SecKeyError, CurvePoint, PubKey, ScalarField, SecKey};
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
pub type Result<T> = std::result::Result<T, KeypairError>;

/// Keypair structure
#[derive(Clone, PartialEq, Eq)]
pub struct Keypair {
    /// Secret key
    pub(crate) secret: SecKey,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_hex() {
        assert_eq!(
            Keypair::from_hex(""),
            Err(KeypairError::SecretKey(SecKeyError::SecretKeyBytes))
        );
        assert_eq!(
            Keypair::from_hex("1428fadcf0c02396e620f14f176fddb5d769b7de2027469d027a80142ef8f07"),
            Err(KeypairError::SecretKey(SecKeyError::SecretKeyHex))
        );
        assert_eq!(
            Keypair::from_hex("0f5314f176fddb5d769b7de2027469d027ad428fadcf0c02396e6280142efb7d8"),
            Err(KeypairError::SecretKey(SecKeyError::SecretKeyHex))
        );
        assert_eq!(
            Keypair::from_hex("g64244176fddb5d769b7de2027469d027ad428fadcf0c02396e6280142efb7d8"),
            Err(KeypairError::SecretKey(SecKeyError::SecretKeyHex))
        );
        assert_eq!(
            Keypair::from_hex("4244176fddb5d769b7de2027469d027ad428fadcc0c02396e6280142efb718"),
            Err(KeypairError::SecretKey(SecKeyError::SecretKeyBytes))
        );

        Keypair::from_hex("164244176fddb5d769b7de2027469d027ad428fadcc0c02396e6280142efb718")
            .expect("failed to decode keypair secret key");
    }

    #[test]
    fn get_address() {
        macro_rules! assert_get_address_eq {
            ($sec_key_hex:expr, $target_address:expr) => {
                let kp = Keypair::from_hex($sec_key_hex).expect("failed to create keypair");
                assert_eq!(kp.get_address(), $target_address);
            };
        }

        assert_get_address_eq!(
            "164244176fddb5d769b7de2027469d027ad428fadcc0c02396e6280142efb718",
            "B62qnzbXmRNo9q32n4SNu2mpB8e7FYYLH8NmaX6oFCBYjjQ8SbD7uzV"
        );
        assert_get_address_eq!(
            "3ca187a58f09da346844964310c7e0dd948a9105702b716f4d732e042e0c172e",
            "B62qicipYxyEHu7QjUqS7QvBipTs5CzgkYZZZkPoKVYBu6tnDUcE9Zt"
        );
        assert_get_address_eq!(
            "336eb4a19b3d8905824b0f2254fb495573be302c17582748bf7e101965aa4774",
            "B62qrKG4Z8hnzZqp1AL8WsQhQYah3quN1qUj3SyfJA8Lw135qWWg1mi"
        );
        assert_get_address_eq!(
            "1dee867358d4000f1dafa5978341fb515f89eeddbe450bd57df091f1e63d4444",
            "B62qoqiAgERjCjXhofXiD7cMLJSKD8hE8ZtMh4jX5MPNgKB4CFxxm1N"
        );
        assert_get_address_eq!(
            "20f84123a26e58dd32b0ea3c80381f35cd01bc22a20346cc65b0a67ae48532ba",
            "B62qkiT4kgCawkSEF84ga5kP9QnhmTJEYzcfgGuk6okAJtSBfVcjm1M"
        );
        assert_get_address_eq!(
            "3414fc16e86e6ac272fda03cf8dcb4d7d47af91b4b726494dab43bf773ce1779",
            "B62qoG5Yk4iVxpyczUrBNpwtx2xunhL48dydN53A2VjoRwF8NUTbVr4"
        );
    }

    #[test]
    fn to_bytes() {
        let bytes = [
            61, 18, 244, 30, 36, 241, 5, 54, 107, 96, 154, 162, 58, 78, 242, 140, 186, 233, 25, 35,
            145, 119, 39, 94, 162, 123, 208, 202, 189, 29, 235, 209,
        ];
        assert_eq!(
            Keypair::from_bytes(&bytes)
                .expect("failed to decode keypair")
                .to_bytes(),
            bytes
        );

        // negative test (too many bytes)
        assert_eq!(
            Keypair::from_bytes(&[
                61, 18, 244, 30, 36, 241, 5, 54, 107, 96, 154, 162, 58, 78, 242, 140, 186, 233, 25,
                35, 145, 119, 39, 94, 162, 123, 208, 202, 189, 29, 235, 209, 0
            ]),
            Err(KeypairError::SecretKey(SecKeyError::SecretKeyBytes))
        );

        // negative test (too few bytes)
        assert_eq!(
            Keypair::from_bytes(&[
                61, 18, 244, 30, 36, 241, 5, 54, 107, 96, 154, 162, 58, 78, 242, 140, 186, 233, 25,
                35, 145, 119, 39, 94, 162, 123, 208, 202, 189, 29
            ]),
            Err(KeypairError::SecretKey(SecKeyError::SecretKeyBytes))
        );
    }
}
