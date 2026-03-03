//! Mina signature structure and associated helpers
//!
//! This module provides the core signature functionality for the Mina protocol.
//! Signatures in Mina are based on Schnorr signatures over elliptic curves,
//! specifically using the Pallas curve and its associated scalar field.
//!
//! The signature scheme is compatible with the signature scheme used in the
//! Mina protocol, and follows the standard Schnorr signature construction.
//!
//! # Examples
//!
//! ```rust
//! use mina_signer::{Signature, BaseField, ScalarField};
//!
//! // Create a new signature from field elements
//! let rx = BaseField::from(42u64);
//! let s = ScalarField::from(123u64);
//! let signature = Signature::new(rx, s);
//!
//! // Display signature as hexadecimal string
//! println!("Signature: {}", signature);
//! ```

use crate::{BaseField, ScalarField};
use ark_ff::One;
use core::fmt;
use o1_utils::FieldHelpers;

/// A Schnorr signature for the Mina protocol.
///
/// This structure represents a cryptographic signature that consists of two
/// components:
/// - `rx`: The x-coordinate of the commitment point R, represented as a base
///   field element
/// - `s`: The signature scalar, computed as `s = k + r * private_key` where `k`
///   is a random nonce
///
/// The signature follows the standard Schnorr signature scheme adapted for
/// Mina's elliptic curve choice (Pallas curve). This ensures compatibility with
/// the Mina blockchain's verification requirements.
///
/// # Security Properties
///
/// - **Unforgeability**: Cannot be forged without knowledge of the private key
/// - **Non-malleability**: Signature cannot be modified to create a valid
///   signature for a different message
/// - **Deterministic**: Given the same message and private key, produces the
///   same signature (when using deterministic nonce generation)
///
/// # Field Element Encoding
///
/// - `rx` is encoded as a base field element (typically Fp for Pallas curve)
/// - `s` is encoded as a scalar field element (typically Fq for Pallas curve)
///
/// Both components are essential for signature verification and must be
/// preserved with full precision during serialization and transmission.
#[derive(Clone, Eq, fmt::Debug, PartialEq)]
pub struct Signature {
    /// The x-coordinate of the commitment point R from the Schnorr signature.
    ///
    /// This value is derived from the random nonce used during signing and
    /// represents the x-coordinate of the point R = k * G, where k is the nonce
    /// and G is the generator point of the elliptic curve.
    ///
    /// The rx component is crucial for signature verification as it's used to
    /// reconstruct the commitment point during the verification process.
    pub rx: BaseField,

    /// The signature scalar component.
    ///
    /// This scalar is computed as `s = k + r * private_key (mod n)`, where:
    /// - `k` is the random nonce used during signing
    /// - `r` is the challenge derived from the commitment point and message
    /// - `private_key` is the signer's secret key
    /// - `n` is the order of the scalar field
    ///
    /// The scalar `s` proves knowledge of the private key without revealing it,
    /// making it the core component that provides the signature's authenticity.
    pub s: ScalarField,
}

impl Signature {
    /// Creates a new signature from the given field elements.
    ///
    /// This constructor builds a signature from its two core components:
    /// the commitment point's x-coordinate and the signature scalar.
    ///
    /// # Arguments
    ///
    /// * `rx` - The x-coordinate of the commitment point R, as a base field
    ///   element
    /// * `s` - The signature scalar, as a scalar field element
    ///
    /// # Returns
    ///
    /// A new `Signature` instance containing the provided components.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use mina_signer::{Signature, BaseField, ScalarField};
    ///
    /// let rx = BaseField::from(123u64);
    /// let s = ScalarField::from(456u64);
    /// let signature = Signature::new(rx, s);
    ///
    /// assert_eq!(signature.rx, rx);
    /// assert_eq!(signature.s, s);
    /// ```
    ///
    /// # Security Note
    ///
    /// This constructor does not validate that the provided components form
    /// a valid signature for any particular message or public key. It simply
    /// creates the data structure. Signature validation must be performed
    /// separately using appropriate verification functions.
    #[must_use]
    pub const fn new(rx: BaseField, s: ScalarField) -> Self {
        Self { rx, s }
    }

    /// Create a dummy signature, whose components are both equal to one.
    /// Use it with caution.
    #[must_use]
    pub fn dummy() -> Self {
        Self {
            rx: BaseField::one(),
            s: ScalarField::one(),
        }
    }
}

impl fmt::Display for Signature {
    /// Formats the signature as a hexadecimal string.
    ///
    /// Returns the signature as concatenated hex-encoded bytes in big-endian
    /// order: `rx || s`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut rx_bytes = self.rx.to_bytes();
        let mut s_bytes = self.s.to_bytes();
        rx_bytes.reverse();
        s_bytes.reverse();

        write!(f, "{}{}", hex::encode(rx_bytes), hex::encode(s_bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{format, string::ToString};

    #[test]
    fn test_signature_encoding() {
        // Test with small values to verify big-endian encoding and rx || s
        // order
        let rx = BaseField::from(4u64);
        let s = ScalarField::from(42u64);
        let signature = Signature::new(rx, s);

        let encoded = signature.to_string();

        // Should always be 128 hex characters (64 bytes total)
        assert_eq!(
            encoded.len(),
            128,
            "Signature encoding should be exactly 128 hex characters"
        );

        // Split into rx and s parts (64 chars each)
        let (encoded_rx, encoded_s) = encoded.split_at(64);

        // Verify rx part ends with "04" (4 in big-endian hex, padded to 32
        // bytes)
        assert!(
            encoded_rx.ends_with("04"),
            "rx component should end with '04' for value 4"
        );

        // Verify s part ends with "2a" (42 in big-endian hex, padded to 32
        // bytes)
        assert!(
            encoded_s.ends_with("2a"),
            "s component should end with '2a' for value 42"
        );

        // Test with another small value to confirm pattern
        let rx2 = BaseField::from(255u64); // 0xff
        let s2 = ScalarField::from(256u64); // 0x100
        let signature2 = Signature::new(rx2, s2);
        let encoded2 = signature2.to_string();

        let (hex_rx_part, hex_s_part) = encoded2.split_at(64);
        assert!(
            hex_rx_part.ends_with("ff"),
            "rx should end with 'ff' for value 255"
        );
        assert!(
            hex_s_part.ends_with("0100"),
            "s should end with '0100' for value 256"
        );

        // Verify the order: rx comes first, then s
        assert_ne!(
            encoded_rx, encoded_s,
            "rx and s components should be different"
        );
        assert_eq!(
            encoded,
            format!("{encoded_rx}{encoded_s}"),
            "Encoding should be rx followed by s"
        );
    }
}
