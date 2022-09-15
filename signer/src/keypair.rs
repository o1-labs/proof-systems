//! Keypair structures and algorithms
//!
//! Definition of secret key, keypairs and related helpers

use crate::{CurvePoint, PubKey, ScalarField, SecKey};
use ark_ec::{AffineCurve, ProjectiveCurve};
use core::fmt;
use o1_utils::FieldHelpers;
use rand::{self, CryptoRng, RngCore};
use thiserror::Error;

/// Keypair error
#[allow(clippy::module_name_repetitions)]
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum KeypairError {
    /// Invalid secret key hex
    #[error("invalid secret key hex")]
    SecretKeyHex,
    /// Invalid secret key bytes
    #[error("Invalid secret key bytes")]
    SecretKeyBytes,
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
    /// Create a keypair from scalar field `secret` element and curve point `public`
    /// Note: Does not check point `public` is on curve
    #[allow(clippy::needless_pass_by_value)]
    #[must_use]
    pub fn from_parts_unsafe(secret: ScalarField, public: CurvePoint) -> Self {
        Self {
            secret: SecKey::new(secret),
            public: PubKey::from_point_unsafe(public),
        }
    }

    /// Generate a random keypair
    pub fn rand(rng: &mut (impl RngCore + CryptoRng)) -> Self {
        let sec_key: SecKey = SecKey::rand(rng);
        let scalar = sec_key.into_scalar();
        let public: CurvePoint = CurvePoint::prime_subgroup_generator()
            .mul(scalar)
            .into_affine();

        // Safe in this case b/c point must be on curve
        Self::from_parts_unsafe(scalar, public)
    }

    /// Deserialize a keypair from secret key hex
    ///
    /// # Errors
    ///
    /// Will give error if `hex` string does not match certain requirements.
    pub fn from_hex(secret_hex: &str) -> Result<Self> {
        let mut bytes: Vec<u8> = hex::decode(secret_hex).map_err(|_| KeypairError::SecretKeyHex)?;
        bytes.reverse(); // mina scalars hex format is in big-endian order

        let secret = ScalarField::from_bytes(&bytes).map_err(|_| KeypairError::SecretKeyBytes)?;
        let public: CurvePoint = CurvePoint::prime_subgroup_generator()
            .mul(secret)
            .into_affine();

        if !public.is_on_curve() {
            return Err(KeypairError::NonCurvePoint);
        }

        // Safe now because we checked point is on the curve
        Ok(Keypair::from_parts_unsafe(secret, public))
    }

    /// Obtain the Mina address corresponding to the keypair's public key
    #[must_use]
    pub fn get_address(self) -> String {
        self.public.into_address()
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
        assert_eq!(Keypair::from_hex(""), Err(KeypairError::SecretKeyBytes));
        assert_eq!(
            Keypair::from_hex("1428fadcf0c02396e620f14f176fddb5d769b7de2027469d027a80142ef8f07"),
            Err(KeypairError::SecretKeyHex)
        );
        assert_eq!(
            Keypair::from_hex("0f5314f176fddb5d769b7de2027469d027ad428fadcf0c02396e6280142efb7d8"),
            Err(KeypairError::SecretKeyHex)
        );
        assert_eq!(
            Keypair::from_hex("g64244176fddb5d769b7de2027469d027ad428fadcf0c02396e6280142efb7d8"),
            Err(KeypairError::SecretKeyHex)
        );
        assert_eq!(
            Keypair::from_hex("dd4244176fddb5d769b7de2027469d027ad428fadcc0c02396e6280142efb718"),
            Err(KeypairError::SecretKeyBytes)
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
}
