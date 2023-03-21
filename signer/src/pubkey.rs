//! Public key structures and algorithms
//!
//! Definition of public key structure and helpers

use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::{BigInteger, PrimeField, Zero};
use bs58;
use core::fmt;
use sha2::{Digest, Sha256};
use std::ops::Neg;
use thiserror::Error;

use crate::{BaseField, CurvePoint, ScalarField, SecKey};
use o1_utils::FieldHelpers;

/// Public key errors
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum PubKeyError {
    /// Invalid address length
    #[error("invalid address length")]
    AddressLength,
    /// Invalid address base58
    #[error("invalid address base58")]
    AddressBase58,
    /// Invalid raw address bytes length
    #[error("invalid raw address bytes length")]
    AddressRawByteLength,
    /// Invalid address checksum
    #[error("invalid address checksum")]
    AddressChecksum,
    /// Invalid address version
    #[error("invalid address version")]
    AddressVersion,
    /// Invalid x-coordinate bytes
    #[error("invalid x-coordinate bytes")]
    XCoordinateBytes,
    /// Invalid x-coordinate
    #[error("invalid x-coordinate")]
    XCoordinate,
    /// Point not on curve
    #[error("point not on curve")]
    YCoordinateBytes,
    /// Invalid y-coordinate
    #[error("invalid y-coordinate bytes")]
    YCoordinateParityBytes,
    /// Invalid y-coordinate parity
    #[error("invalid y-coordinate parity bytes")]
    YCoordinateParity,
    /// Invalid y-coordinate parity
    #[error("invalid y-coordinate parity")]
    NonCurvePoint,
    /// Invalid hex
    #[error("invalid public key hex")]
    Hex,
    /// Invalid secret key
    #[error("invalid secret key")]
    SecKey,
}
/// Public key Result
pub type Result<T> = std::result::Result<T, PubKeyError>;

/// Length of Mina addresses
pub const MINA_ADDRESS_LEN: usize = 55;
const MINA_ADDRESS_RAW_LEN: usize = 40;

/// Public key
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PubKey(CurvePoint);

impl PubKey {
    /// Create public key from curve point
    /// Note: Does not check point is on curve
    pub fn from_point_unsafe(point: CurvePoint) -> Self {
        Self(point)
    }

    /// Deserialize public key from bytes
    /// # Errors
    ///
    /// Will give error if `bytes` do not match certain requirements.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != BaseField::size_in_bytes() * 2 {
            return Err(PubKeyError::YCoordinateBytes);
        }
        let x = BaseField::from_bytes(&bytes[0..BaseField::size_in_bytes()])
            .map_err(|_| PubKeyError::XCoordinateBytes)?;
        let y = BaseField::from_bytes(&bytes[BaseField::size_in_bytes()..])
            .map_err(|_| PubKeyError::YCoordinateBytes)?;
        let pt = CurvePoint::get_point_from_x(x, y.0.is_odd()).ok_or(PubKeyError::XCoordinate)?;
        if pt.y != y {
            return Err(PubKeyError::NonCurvePoint);
        }

        let public = CurvePoint::new(x, y, pt.infinity);
        if !public.is_on_curve() {
            return Err(PubKeyError::NonCurvePoint);
        }

        // Safe now because we checked point is on the curve
        Ok(PubKey::from_point_unsafe(public))
    }

    /// Deserialize public key from hex
    ///
    /// # Errors
    ///
    /// Will give error if `hex` string does not match certain requirements.
    pub fn from_hex(public_hex: &str) -> Result<Self> {
        let bytes: Vec<u8> = hex::decode(public_hex).map_err(|_| PubKeyError::Hex)?;
        PubKey::from_bytes(&bytes)
    }

    /// Create public key from a secret key
    pub fn from_secret_key(secret_key: SecKey) -> Result<Self> {
        if secret_key.clone().into_scalar() == ScalarField::zero() {
            return Err(PubKeyError::SecKey);
        }
        let pt = CurvePoint::prime_subgroup_generator()
            .mul(secret_key.into_scalar())
            .into_affine();
        if !pt.is_on_curve() {
            return Err(PubKeyError::NonCurvePoint);
        }
        Ok(PubKey::from_point_unsafe(pt))
    }

    /// Deserialize Mina address into public key
    ///
    /// # Errors
    ///
    /// Will give error if `address` string does not match certain requirements.
    pub fn from_address(address: &str) -> Result<Self> {
        if address.len() != MINA_ADDRESS_LEN {
            return Err(PubKeyError::AddressLength);
        }

        let bytes = bs58::decode(address)
            .into_vec()
            .map_err(|_| PubKeyError::AddressBase58)?;

        if bytes.len() != MINA_ADDRESS_RAW_LEN {
            return Err(PubKeyError::AddressRawByteLength);
        }

        let (raw, checksum) = (&bytes[..bytes.len() - 4], &bytes[bytes.len() - 4..]);
        let hash = Sha256::digest(&Sha256::digest(raw)[..]);
        if checksum != &hash[..4] {
            return Err(PubKeyError::AddressChecksum);
        }

        let (version, x_bytes, y_parity) = (
            &raw[..3],
            &raw[3..bytes.len() - 5],
            raw[bytes.len() - 5] == 0x01,
        );
        if version != [0xcb, 0x01, 0x01] {
            return Err(PubKeyError::AddressVersion);
        }

        let x = BaseField::from_bytes(x_bytes).map_err(|_| PubKeyError::XCoordinateBytes)?;
        let mut pt = CurvePoint::get_point_from_x(x, y_parity).ok_or(PubKeyError::XCoordinate)?;

        if pt.y.into_repr().is_even() == y_parity {
            pt.y = pt.y.neg();
        }

        if !pt.is_on_curve() {
            return Err(PubKeyError::NonCurvePoint);
        }

        // Safe now because we checked point pt is on curve
        Ok(PubKey::from_point_unsafe(pt))
    }

    /// Borrow public key as curve point
    pub fn point(&self) -> &CurvePoint {
        &self.0
    }

    /// Convert public key into curve point
    pub fn into_point(self) -> CurvePoint {
        self.0
    }

    /// Convert public key into compressed public key
    pub fn into_compressed(&self) -> CompressedPubKey {
        let point = self.0;
        CompressedPubKey {
            x: point.x,
            is_odd: point.y.into_repr().is_odd(),
        }
    }

    /// Serialize public key into corresponding Mina address
    pub fn into_address(&self) -> String {
        let point = self.point();
        into_address(&point.x, point.y.into_repr().is_odd())
    }

    /// Deserialize public key into bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let point = self.point();
        [point.x.to_bytes(), point.y.to_bytes()].concat()
    }

    /// Deserialize public key into hex
    pub fn to_hex(&self) -> String {
        let point = self.point();
        point.x.to_hex() + point.y.to_hex().as_str()
    }
}

impl fmt::Display for PubKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

/// Compressed public keys consist of x-coordinate and y-coordinate parity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompressedPubKey {
    /// X-coordinate
    pub x: BaseField,

    /// Parity of y-coordinate
    pub is_odd: bool,
}

fn into_address(x: &BaseField, is_odd: bool) -> String {
    let mut raw: Vec<u8> = vec![
        0xcb, // version for base58 check
        0x01, // non_zero_curve_point version
        0x01, // compressed_poly version
    ];

    // pub key x-coordinate
    raw.extend(x.to_bytes());

    // pub key y-coordinate parity
    raw.push(u8::from(is_odd));

    // 4-byte checksum
    let hash = Sha256::digest(&Sha256::digest(&raw[..])[..]);
    raw.extend(&hash[..4]);

    // The raw buffer is MINA_ADDRESS_RAW_LEN (= 40) bytes in length
    bs58::encode(raw).into_string()
}

impl CompressedPubKey {
    /// Serialize compressed public key into corresponding Mina address
    pub fn into_address(&self) -> String {
        into_address(&self.x, self.is_odd)
    }

    /// Deserialize compressed public key from bytes
    /// # Errors
    ///
    /// Will give error if `bytes` do not match certain requirements.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let x = BaseField::from_bytes(&bytes[0..BaseField::size_in_bytes()])
            .map_err(|_| PubKeyError::XCoordinateBytes)?;
        let parity_bytes = &bytes[BaseField::size_in_bytes()..];
        if parity_bytes.len() != 1 {
            return Err(PubKeyError::YCoordinateParityBytes);
        }
        let is_odd = if parity_bytes[0] == 0x01 {
            true // Odd
        } else if parity_bytes[0] == 0x00 {
            false // Even
        } else {
            return Err(PubKeyError::YCoordinateParity);
        };
        let public = CurvePoint::get_point_from_x(x, is_odd).ok_or(PubKeyError::XCoordinate)?;
        if !public.is_on_curve() {
            return Err(PubKeyError::NonCurvePoint);
        }

        // Safe now because we checked point is on the curve
        Ok(Self { x, is_odd })
    }

    /// Deserialize compressed public key from hex
    ///
    /// # Errors
    ///
    /// Will give error if `hex` string does not match certain requirements.
    pub fn from_hex(public_hex: &str) -> Result<Self> {
        let bytes: Vec<u8> = hex::decode(public_hex).map_err(|_| PubKeyError::Hex)?;
        Self::from_bytes(&bytes)
    }

    /// Create compressed public key from a secret key
    pub fn from_secret_key(sec_key: SecKey) -> Self {
        // We do not need to check point is on the curve, since it's derived directly from the generator point
        let public = PubKey::from_point_unsafe(
            CurvePoint::prime_subgroup_generator()
                .mul(sec_key.into_scalar())
                .into_affine(),
        );
        public.into_compressed()
    }

    /// Deserialize Mina address into compressed public key (via an uncompressed `PubKey`)
    ///
    /// # Errors
    ///
    /// Will give error if `PubKey::from_address()` returns error.
    pub fn from_address(address: &str) -> Result<Self> {
        Ok(PubKey::from_address(address)?.into_compressed())
    }

    /// The empty [`CompressedPubKey`] value that is used as `public_key` in empty account
    /// and [None] value for calculating the hash of [Option<CompressedPubKey>], etc.
    pub fn empty() -> Self {
        Self {
            x: BaseField::zero(),
            is_odd: false,
        }
    }

    /// Deserialize compressed public key into bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let x_bytes = self.x.to_bytes();
        let is_odd_bytes = vec![if self.is_odd { 0x01u8 } else { 0x00u8 }];
        [x_bytes, is_odd_bytes].concat()
    }

    /// Deserialize compressed public key into hex
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
            PubKey::to_hex(
                &PubKey::from_hex(
                    "44100485d466a4c9f481d43be9a6d4a9a5e97adac19777b14b6b7a81edee39093179f4f12897797cfe78bf2fd6321f36b00bd0592defbf39a199b4168735883c"
                )
                .expect("failed to decode pub key"),
            ),
            "44100485d466a4c9f481d43be9a6d4a9a5e97adac19777b14b6b7a81edee39093179f4f12897797cfe78bf2fd6321f36b00bd0592defbf39a199b4168735883c"
        );

        assert_eq!(
            PubKey::to_hex(
                &PubKey::from_hex(
                    "0c18d735252f4401eb845d08a87d780e9dc6ed053d0e071395277f0a34d45a29125030f6cd465cccf2ebbaabc397a6823932bc55dc1ddf9954c9e78da07c0928"
                )
                .expect("failed to decode pub key"),
            ),
            "0c18d735252f4401eb845d08a87d780e9dc6ed053d0e071395277f0a34d45a29125030f6cd465cccf2ebbaabc397a6823932bc55dc1ddf9954c9e78da07c0928"
        );

        assert_eq!(
            PubKey::from_hex("44100485d466a4c9f281d43be9a6d4a9a5e97adac19777b14b6b7a81edee39093179f4f12897797cfe78bf2fd6321f36b00bd0592defbf39a199b4168735883c"),
            Err(PubKeyError::XCoordinate)
        );

        assert_eq!(
            PubKey::from_hex("44100485d466a4c9f481d43be9a6d4a9a5e97adac19777b14b6b7a81edee39093179f4f12897797cfe78bf2fd6321f36b00bd0592defbf39a199b4168715883c"),
            Err(PubKeyError::NonCurvePoint)
        );

        assert_eq!(
            PubKey::from_hex("z8f71009a6502f89a469a037f14e97386034ea3855877159f29f4a532a2e5f28"),
            Err(PubKeyError::Hex)
        );

        assert_eq!(
            PubKey::from_hex("44100485d466a4c9f481d43be9a6d4aa5e97adac19777b14b6b7a81edee39093179f4f12897797cfe78bf2fd6321f36b00bd0592defbf39a199b4168735883c"),
            Err(PubKeyError::Hex)
        );
    }

    #[test]
    fn from_secret_key() {
        assert_eq!(PubKey::from_secret_key(
                SecKey::from_hex("090dd91a2505081a158782c5a24fef63f326749b383423c29827e465f7ca262b").expect("failed to decode sec key")
            ).expect("failed to decode pub key").to_hex(),
            "3f8c32817851b7c1ad99495463ef5e99c3b3240524f0df3ff7fc41181d849e0086fa821d54de15c523a840c5f62df90aeabb1097b85c6a88e163e9d74e505803"
        );

        assert_eq!(PubKey::from_secret_key(
                SecKey::from_hex("086d78e0e5deb62daeef8e3a5574d52a3d3bff5281b4dd49140564c7d80468c9").expect("failed to decode sec key")
            ).expect("failed to decode pub key").to_hex(),
            "666c450f5e888d3b2341d77b32cb6d0cd4912829ea9c41030d1fd2baff6b9a30c267208638544299e8d369e80b25a24bdd07383b6ea908028d9a406b528d4a01"
        );

        assert_eq!(PubKey::from_secret_key(
                SecKey::from_hex("0859771e9394e96dd6d01d57ef074dc25313e63bd331fa5478a9fed9e24855a0").expect("failed to decode sec key")
            ).expect("failed to decode pub key").to_hex(),
            "6ed0776ab11e3dd3b637cce03a90529e518220132f1a61dd9c0d50aa998abf1d2f43c0f1eb73888ef6f7dac4d7094d3c92cd67abab39b828c5f10aff0b6a0002"
        );
    }

    #[test]
    fn from_address() {
        macro_rules! assert_from_address_check {
            ($address:expr) => {
                let pk = PubKey::from_address($address).expect("failed to create pubkey");
                assert_eq!(pk.into_address(), $address);
            };
        }

        assert_from_address_check!("B62qnzbXmRNo9q32n4SNu2mpB8e7FYYLH8NmaX6oFCBYjjQ8SbD7uzV");
        assert_from_address_check!("B62qicipYxyEHu7QjUqS7QvBipTs5CzgkYZZZkPoKVYBu6tnDUcE9Zt");
        assert_from_address_check!("B62qoG5Yk4iVxpyczUrBNpwtx2xunhL48dydN53A2VjoRwF8NUTbVr4");
        assert_from_address_check!("B62qrKG4Z8hnzZqp1AL8WsQhQYah3quN1qUj3SyfJA8Lw135qWWg1mi");
        assert_from_address_check!("B62qoqiAgERjCjXhofXiD7cMLJSKD8hE8ZtMh4jX5MPNgKB4CFxxm1N");
        assert_from_address_check!("B62qkiT4kgCawkSEF84ga5kP9QnhmTJEYzcfgGuk6okAJtSBfVcjm1M");
    }

    #[test]
    fn to_bytes() {
        let mut bytes = vec![
            68, 16, 4, 133, 212, 102, 164, 201, 244, 129, 212, 59, 233, 166, 212, 169, 165, 233,
            122, 218, 193, 151, 119, 177, 75, 107, 122, 129, 237, 238, 57, 9, 49, 121, 244, 241,
            40, 151, 121, 124, 254, 120, 191, 47, 214, 50, 31, 54, 176, 11, 208, 89, 45, 239, 191,
            57, 161, 153, 180, 22, 135, 53, 136, 60,
        ];
        assert_eq!(
            PubKey::from_bytes(&bytes)
                .expect("failed to decode pub key")
                .to_bytes(),
            bytes
        );

        bytes[0] = 0; // negative test: invalid curve point
        assert_eq!(PubKey::from_bytes(&bytes), Err(PubKeyError::NonCurvePoint));

        bytes[0] = 68;
        let mut bytes = [bytes, vec![255u8, 102u8]].concat(); // negative test: to many bytes
        assert_eq!(
            PubKey::from_bytes(&bytes),
            Err(PubKeyError::YCoordinateBytes)
        );

        bytes.remove(0); // negative test: to few bytes
        bytes.remove(0);
        assert_eq!(
            PubKey::from_bytes(&bytes),
            Err(PubKeyError::XCoordinateBytes)
        );
    }

    #[test]
    fn compressed_from_hex() {
        assert_eq!(PubKey::from_hex(
                "44100485d466a4c9f481d43be9a6d4a9a5e97adac19777b14b6b7a81edee39093179f4f12897797cfe78bf2fd6321f36b00bd0592defbf39a199b4168735883c"
            ).expect("failed to decode pub key").into_address(),
            CompressedPubKey::from_hex(
                "44100485d466a4c9f481d43be9a6d4a9a5e97adac19777b14b6b7a81edee390901"
            ).expect("failed to decode compressed pub key").into_address()
        );

        assert_eq!(PubKey::from_hex(
                "44100485d466a4c9f481d43be9a6d4a9a5e97adac19777b14b6b7a81edee39093179f4f12897797cfe78bf2fd6321f36b00bd0592defbf39a199b4168735883c"
            ).expect("failed to decode pub key").into_compressed(),
            CompressedPubKey::from_hex(
                "44100485d466a4c9f481d43be9a6d4a9a5e97adac19777b14b6b7a81edee390901"
            ).expect("failed to decode compressed pub key")
        );

        assert_ne!(PubKey::from_hex(
                "44100485d466a4c9f481d43be9a6d4a9a5e97adac19777b14b6b7a81edee39093179f4f12897797cfe78bf2fd6321f36b00bd0592defbf39a199b4168735883c"
            ).expect("failed to decode pub key").into_compressed(),
            CompressedPubKey::from_hex( // Invalid parity bit
                "44100485d466a4c9f481d43be9a6d4a9a5e97adac19777b14b6b7a81edee390900"
            ).expect("failed to decode compressed pub key")
        );

        assert_eq!(PubKey::from_hex(
                "0c18d735252f4401eb845d08a87d780e9dc6ed053d0e071395277f0a34d45a29125030f6cd465cccf2ebbaabc397a6823932bc55dc1ddf9954c9e78da07c0928"
            ).expect("failed to decode pub key").into_compressed(),
            CompressedPubKey::from_hex(
                "0c18d735252f4401eb845d08a87d780e9dc6ed053d0e071395277f0a34d45a2900"
            ).expect("failed to decode compressed pub key")
        );

        assert_eq!(
            CompressedPubKey::from_hex(
                // Missing parity bit
                "0c18d735252f4401eb845d08a87d780e9dc6ed053d0e071395277f0a34d45a29"
            ),
            Err(PubKeyError::YCoordinateParityBytes)
        );

        assert_eq!(
            CompressedPubKey::from_hex(
                // Wrong parity bytes
                "0c18d735252f4401eb845d08a87d780e9dc6ed053d0e071395277f0a34d45a290101"
            ),
            Err(PubKeyError::YCoordinateParityBytes)
        );

        assert_eq!(
            CompressedPubKey::from_hex(
                // Invalid parity byte
                "0c18d735252f4401eb845d08a87d780e9dc6ed053d0e071395277f0a34d45a2902"
            ),
            Err(PubKeyError::YCoordinateParity)
        );

        assert!(CompressedPubKey::from_hex(
            // OK parity byte (odd)
            "0c18d735252f4401eb845d08a87d780e9dc6ed053d0e071395277f0a34d45a2900"
        )
        .is_ok());

        assert!(CompressedPubKey::from_hex(
            // OK parity byte (odd)
            "0c18d735252f4401eb845d08a87d780e9dc6ed053d0e071395277f0a34d45a2901"
        )
        .is_ok());

        assert_ne!(PubKey::from_hex(
                "0c18d735252f4401eb845d08a87d780e9dc6ed053d0e071395277f0a34d45a29125030f6cd465cccf2ebbaabc397a6823932bc55dc1ddf9954c9e78da07c0928"
            ).expect("failed to decode pub key").into_compressed(),
            CompressedPubKey::from_hex(
                "0c18d735252f4401eb845d08a87d780e9dc6ed053d0e071395277f0a34d45a2901"
            ).expect("failed to decode compressed pub key")
        );
    }

    #[test]
    fn compressed_to_bytes() {
        let mut bytes = vec![
            68, 16, 4, 133, 212, 102, 164, 201, 244, 129, 212, 59, 233, 166, 212, 169, 165, 233,
            122, 218, 193, 151, 119, 177, 75, 107, 122, 129, 237, 238, 57, 9, 1,
        ];
        assert_eq!(
            CompressedPubKey::from_bytes(&bytes)
                .expect("failed to decode pub key")
                .to_bytes(),
            bytes
        );

        bytes[4] = 73; // negative test: invalid x
        assert_eq!(
            CompressedPubKey::from_bytes(&bytes),
            Err(PubKeyError::XCoordinate)
        );

        bytes[0] = 212;
        let mut bytes = [bytes, vec![255u8]].concat(); // negative test: to many bytes
        assert_eq!(
            CompressedPubKey::from_bytes(&bytes),
            Err(PubKeyError::YCoordinateParityBytes)
        );

        bytes.remove(0); // negative test: to few bytes
        bytes.remove(0);
        assert_eq!(
            CompressedPubKey::from_bytes(&bytes),
            Err(PubKeyError::XCoordinateBytes)
        );
    }
}
