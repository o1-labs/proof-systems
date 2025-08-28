//! Mina signature structure and associated helpers

use crate::{BaseField, ScalarField};
use ark_ff::One;
use core::fmt;
use o1_utils::FieldHelpers;

/// Signature structure
#[derive(Clone, Eq, fmt::Debug, PartialEq)]
pub struct Signature {
    /// Base field component
    pub rx: BaseField,

    /// Scalar field component
    pub s: ScalarField,
}

impl Signature {
    /// Create a new signature
    pub fn new(rx: BaseField, s: ScalarField) -> Self {
        Self { rx, s }
    }

    /// Create a dummy signature, whose components are both equal to one.
    /// Use it with caution.
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
        let (rx_hex, s_hex) = encoded.split_at(64);

        // Verify rx part ends with "04" (4 in big-endian hex, padded to 32
        // bytes)
        assert!(
            rx_hex.ends_with("04"),
            "rx component should end with '04' for value 4"
        );

        // Verify s part ends with "2a" (42 in big-endian hex, padded to 32
        // bytes)
        assert!(
            s_hex.ends_with("2a"),
            "s component should end with '2a' for value 42"
        );

        // Test with another small value to confirm pattern
        let rx2 = BaseField::from(255u64); // 0xff
        let s2 = ScalarField::from(256u64); // 0x100
        let signature2 = Signature::new(rx2, s2);
        let encoded2 = signature2.to_string();

        let (rx2_hex, s2_hex) = encoded2.split_at(64);
        assert!(
            rx2_hex.ends_with("ff"),
            "rx should end with 'ff' for value 255"
        );
        assert!(
            s2_hex.ends_with("0100"),
            "s should end with '0100' for value 256"
        );

        // Verify the order: rx comes first, then s
        assert_ne!(rx_hex, s_hex, "rx and s components should be different");
        assert_eq!(
            encoded,
            format!("{}{}", rx_hex, s_hex),
            "Encoding should be rx followed by s"
        );
    }
}
