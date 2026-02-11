//! Bit operations on big integers.
//!
//! In particular, it gives XOR and NOT for `BigUint`.
use num_bigint::BigUint;

/// Helpers for [`BigUint`]
pub trait BigUintHelpers<Rhs = Self> {
    /// Returns the minimum number of bits required to represent a `BigUint`.
    /// As opposed to `BigUint::bits`, this function returns 1 for the input zero
    fn bitlen(&self) -> usize;

    /// Creates a `BigUint` from an hexadecimal string in big endian
    fn from_hex(s: &str) -> Self;
}

impl BigUintHelpers for BigUint {
    #[allow(clippy::cast_possible_truncation)]
    fn bitlen(&self) -> usize {
        if self.to_bytes_le() == [0u8] {
            1
        } else {
            self.bits() as usize
        }
    }
    fn from_hex(s: &str) -> Self {
        Self::parse_bytes(s.as_bytes(), 16).unwrap()
    }
}
