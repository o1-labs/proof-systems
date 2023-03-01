//! This module provides a set of functions to perform bit operations on big integers.
//! In particular, it gives XOR and NOT for BigUint.
use num_bigint::BigUint;

/// Helpers for BigUint
pub trait BigUintHelpers<Rhs = Self> {
    /// Returns the minimum number of bits required to represent a BigUint
    /// As opposed to BigUint::bits, this function returns 1 for the input zero
    fn bitlen(&self) -> usize;
}

impl BigUintHelpers for BigUint {
    fn bitlen(&self) -> usize {
        if self.to_bytes_le() == [0u8] {
            1
        } else {
            self.bits() as usize
        }
    }
}
