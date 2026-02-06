//! Mina base58check encoding and decoding.
//!
//! Implements the base58check scheme used by the Mina protocol: a
//! single version byte followed by the payload, with a 4-byte
//! double-SHA256 checksum appended before base58 encoding.

#![no_std]
#![deny(missing_docs)]
#![deny(unsafe_code)]
#![deny(clippy::all)]
#![deny(clippy::pedantic)]
#![deny(clippy::nursery)]

extern crate alloc;

/// Version bytes for Mina base58check encodings.
pub mod version;

use alloc::{format, string::String, vec::Vec};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use thiserror::Error;

/// Errors that can occur when decoding a base58check string.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    /// The input is not valid base58.
    ///
    /// The contained string carries the detail from the underlying
    /// `bs58` decoder (e.g. invalid character and position).
    #[error("invalid base58: {0}")]
    InvalidBase58(String),
    /// The decoded data is shorter than the 5-byte minimum
    /// (1 version byte + 4 checksum bytes).
    #[error("decoded data too short")]
    TooShort,
    /// The trailing 4-byte checksum does not match the data.
    #[error("invalid checksum")]
    InvalidChecksum,
    /// The version byte does not match the expected value.
    #[error("invalid version byte: expected {expected:#04x}, found {found:#04x}")]
    InvalidVersion {
        /// The version byte that was expected.
        expected: u8,
        /// The version byte that was found.
        found: u8,
    },
}

/// Double-SHA256 checksum of `data`.
#[must_use]
pub(crate) fn checksum(data: &[u8]) -> [u8; 4] {
    let hash = Sha256::digest(&Sha256::digest(data)[..]);
    let mut out = [0u8; 4];
    out.copy_from_slice(&hash[..4]);
    out
}

/// Constant-time comparison of two 4-byte checksums.
///
/// Uses [`subtle::ConstantTimeEq`] to prevent timing side-channels
/// that could reveal how many leading checksum bytes matched.
fn checksum_verify(got: [u8; 4], expected: [u8; 4]) -> bool {
    got.ct_eq(&expected).into()
}

/// Encode `payload` with a leading `version` byte in base58check.
///
/// Prepends the version byte, computes a 4-byte double-SHA256 checksum
/// over `[version || payload]`, appends it, and base58-encodes.
#[must_use]
pub fn encode(version: u8, payload: &[u8]) -> String {
    let mut buf = Vec::with_capacity(1 + payload.len() + 4);
    buf.push(version);
    buf.extend_from_slice(payload);
    let cs = checksum(&buf);
    buf.extend_from_slice(&cs);
    bs58::encode(buf).into_string()
}

/// Decode a base58check string, returning `(version, payload)`.
///
/// # Errors
///
/// Returns an error if the input is not valid base58, is too short,
/// or has an invalid checksum.
#[must_use = "decoding result must be used"]
pub fn decode(b58: &str) -> Result<(u8, Vec<u8>), DecodeError> {
    let mut raw = decode_raw(b58)?;
    let version = raw[0];
    raw.drain(..1);
    Ok((version, raw))
}

/// Decode a base58check string and verify the version byte.
///
/// # Errors
///
/// Returns an error if decoding fails or the version byte does not
/// match `expected`.
#[must_use = "decoding result must be used"]
pub fn decode_version(b58: &str, expected: u8) -> Result<Vec<u8>, DecodeError> {
    let (version, payload) = decode(b58)?;
    if version != expected {
        return Err(DecodeError::InvalidVersion {
            expected,
            found: version,
        });
    }
    Ok(payload)
}

/// Encode raw bytes (which already contain any version/structure bytes)
/// with an appended 4-byte double-SHA256 checksum.
#[must_use]
pub fn encode_raw(raw: &[u8]) -> String {
    let cs = checksum(raw);
    let mut buf = Vec::with_capacity(raw.len() + 4);
    buf.extend_from_slice(raw);
    buf.extend_from_slice(&cs);
    bs58::encode(buf).into_string()
}

/// Decode a base58check string, verify the checksum, and return the raw
/// bytes (without the trailing checksum but including any version bytes).
///
/// # Errors
///
/// Returns an error if the input is not valid base58, is too short,
/// or has an invalid checksum.
#[must_use = "decoding result must be used"]
pub fn decode_raw(b58: &str) -> Result<Vec<u8>, DecodeError> {
    let mut bytes = bs58::decode(b58)
        .into_vec()
        .map_err(|e| DecodeError::InvalidBase58(format!("{e}")))?;
    if bytes.len() < 5 {
        return Err(DecodeError::TooShort);
    }
    let data_len = bytes.len() - 4;
    let got = [
        bytes[data_len],
        bytes[data_len + 1],
        bytes[data_len + 2],
        bytes[data_len + 3],
    ];
    if !checksum_verify(got, checksum(&bytes[..data_len])) {
        return Err(DecodeError::InvalidChecksum);
    }
    bytes.truncate(data_len);
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ================================================================
    // checksum tests
    // ================================================================

    #[test]
    fn test_checksum_is_deterministic() {
        let data = b"hello world";
        assert_eq!(checksum(data), checksum(data));
    }

    #[test]
    fn test_checksum_differs_for_different_data() {
        assert_ne!(checksum(b"aaa"), checksum(b"bbb"));
    }

    #[test]
    fn test_checksum_is_four_bytes() {
        let cs = checksum(b"any data");
        assert_eq!(cs.len(), 4);
    }

    #[test]
    fn test_checksum_verify_equal() {
        assert!(checksum_verify(
            [0xAA, 0xBB, 0xCC, 0xDD],
            [0xAA, 0xBB, 0xCC, 0xDD]
        ));
    }

    #[test]
    fn test_checksum_verify_rejects_each_byte() {
        let expected = [0xAA, 0xBB, 0xCC, 0xDD];
        for i in 0..4 {
            let mut bad = expected;
            bad[i] ^= 0x01;
            assert!(
                !checksum_verify(bad, expected),
                "byte {i} flip not detected"
            );
        }
    }
}
