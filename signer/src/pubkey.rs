//! Public key structures and algorithms
//!
//! Definition of public key structure and helpers

extern crate alloc;

use crate::{BaseField, CurvePoint, ScalarField, SecKey};
use alloc::{string::String, vec, vec::Vec};
use ark_ec::{short_weierstrass::Affine, AffineRepr, CurveGroup};
use ark_ff::{BigInteger, PrimeField, Zero};
use bs58;
use core::{
    fmt,
    ops::{Mul, Neg},
};
use o1_utils::FieldHelpers;
use sha2::{Digest, Sha256};
use thiserror::Error;

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
pub type Result<T> = core::result::Result<T, PubKeyError>;

/// Length of Mina addresses
pub const MINA_ADDRESS_LEN: usize = 55;
const MINA_ADDRESS_RAW_LEN: usize = 40;

/// Public key
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PubKey(CurvePoint);

impl PubKey {
    /// Create public key from curve point
    /// Note: Does not check point is on curve
    #[allow(clippy::needless_pass_by_value)]
    #[must_use]
    pub const fn from_point_unsafe(point: CurvePoint) -> Self {
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
        let pt = CurvePoint::get_point_from_x_unchecked(x, y.0.is_odd())
            .ok_or(PubKeyError::XCoordinate)?;
        if pt.y != y {
            return Err(PubKeyError::NonCurvePoint);
        }

        let public = Affine {
            x,
            y,
            infinity: pt.infinity,
        };
        if !public.is_on_curve() {
            return Err(PubKeyError::NonCurvePoint);
        }

        // Safe now because we checked point is on the curve
        Ok(Self::from_point_unsafe(public))
    }

    /// Deserialize public key from hex
    ///
    /// # Errors
    ///
    /// Will give error if `hex` string does not match certain requirements.
    pub fn from_hex(public_hex: &str) -> Result<Self> {
        let bytes: Vec<u8> = hex::decode(public_hex).map_err(|_| PubKeyError::Hex)?;
        Self::from_bytes(&bytes)
    }

    /// Create public key from a secret key
    ///
    /// # Errors
    ///
    /// Returns [`PubKeyError::SecKey`] if the scalar is zero, or
    /// [`PubKeyError::NonCurvePoint`] if the derived point is not on the curve.
    pub fn from_secret_key(secret_key: &SecKey) -> Result<Self> {
        if *secret_key.scalar() == ScalarField::zero() {
            return Err(PubKeyError::SecKey);
        }
        let pt = CurvePoint::generator()
            .mul(*secret_key.scalar())
            .into_affine();
        if !pt.is_on_curve() {
            return Err(PubKeyError::NonCurvePoint);
        }
        Ok(Self::from_point_unsafe(pt))
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
        let mut pt =
            CurvePoint::get_point_from_x_unchecked(x, y_parity).ok_or(PubKeyError::XCoordinate)?;

        if pt.y.into_bigint().is_even() == y_parity {
            pt.y = pt.y.neg();
        }

        if !pt.is_on_curve() {
            return Err(PubKeyError::NonCurvePoint);
        }

        // Safe now because we checked point pt is on curve
        Ok(Self::from_point_unsafe(pt))
    }

    /// Borrow public key as curve point
    pub const fn point(&self) -> &CurvePoint {
        &self.0
    }

    /// Convert public key into curve point
    pub const fn into_point(self) -> CurvePoint {
        self.0
    }

    /// Convert public key into compressed public key
    #[must_use]
    pub fn into_compressed(&self) -> CompressedPubKey {
        let point = self.0;
        CompressedPubKey {
            x: point.x,
            is_odd: point.y.into_bigint().is_odd(),
        }
    }

    /// Serialize public key into corresponding Mina address
    #[must_use]
    pub fn into_address(&self) -> String {
        let point = self.point();
        into_address(&point.x, point.y.into_bigint().is_odd())
    }

    /// Deserialize public key into bytes
    ///
    /// # Panics
    ///
    /// Panics if the field element byte conversion fails.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let point = self.point();
        [point.x.to_bytes(), point.y.to_bytes()].concat()
    }

    /// Deserialize public key into hex
    ///
    /// # Panics
    ///
    /// Panics if the field element byte conversion fails.
    #[must_use]
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
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
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
    #[must_use]
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
        let public =
            CurvePoint::get_point_from_x_unchecked(x, is_odd).ok_or(PubKeyError::XCoordinate)?;
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
    #[must_use]
    pub fn from_secret_key(sec_key: SecKey) -> Self {
        // We do not need to check point is on the curve, since it's derived
        // directly from the generator point
        let public = PubKey::from_point_unsafe(
            CurvePoint::generator()
                .mul(sec_key.into_scalar())
                .into_affine(),
        );
        public.into_compressed()
    }

    /// Deserialize Mina address into compressed public key (via an uncompressed
    /// `PubKey`)
    ///
    /// # Errors
    ///
    /// Will give error if `PubKey::from_address()` returns error.
    pub fn from_address(address: &str) -> Result<Self> {
        Ok(PubKey::from_address(address)?.into_compressed())
    }

    /// The empty [`CompressedPubKey`] value that is used as `public_key` in
    /// empty account and `None` value for calculating the hash of
    /// `Option<CompressedPubKey>`, etc.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            x: BaseField::zero(),
            is_odd: false,
        }
    }

    /// Deserialize compressed public key into bytes
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let x_bytes = self.x.to_bytes();
        let is_odd_bytes = vec![u8::from(self.is_odd)];
        [x_bytes, is_odd_bytes].concat()
    }

    /// Deserialize compressed public key into hex
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }
}
