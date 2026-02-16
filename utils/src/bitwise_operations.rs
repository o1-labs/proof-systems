//! This module provides a set of functions to perform bit operations on big integers.
//! In particular, it gives XOR and NOT for `BigUint`.
use num_bigint::BigUint;
use std::cmp::{max, Ordering};

use crate::BigUintHelpers;

/// Bitwise operations
pub trait BitwiseOps<Rhs = Self> {
    /// Bitwise XOR of two `BigUint` inputs
    fn bitwise_xor(input1: &Rhs, input: &Rhs) -> Rhs;

    /// Conjunction of the bits of two `BigUint` inputs for a given number of bytes
    fn bitwise_and(input1: &Rhs, input: &Rhs, bytes: usize) -> Rhs;

    /// Negate the bits of a Self input
    /// If it provides a larger desired `bits` than the input length then it takes the padded input of `bits` length.
    /// Otherwise it only takes the bits of the input.
    fn bitwise_not(input: &Rhs, bits: Option<usize>) -> Rhs;
}

impl BitwiseOps for BigUint {
    fn bitwise_xor(input1: &Self, input2: &Self) -> Self {
        // Pad to equal size in bytes
        let bytes1 = input1.to_bytes_le().len();
        let bytes2 = input2.to_bytes_le().len();
        let in1 = to_padded_bytes(input1, bytes2);
        let in2 = to_padded_bytes(input2, bytes1);
        Self::from_bytes_le(
            &in1.iter()
                .zip(in2.iter())
                .map(|(b1, b2)| b1 ^ b2)
                .collect::<Vec<u8>>(),
        )
    }

    #[allow(clippy::cast_possible_truncation)]
    fn bitwise_not(input: &Self, bits: Option<usize>) -> Self {
        // pad if needed / desired
        // first get the number of bits of the input,
        // take into account that BigUint::bits() returns 0 if the input is 0
        let in_bits = input.bitlen();
        let bits = max(in_bits, bits.unwrap_or(0));
        // build vector of bits in little endian (least significant bit in position 0)
        let mut bit_vec = vec![];
        // negate each of the bits of the input
        (0..bits).for_each(|i| bit_vec.push(!bit_at(input, i as u32)));
        ToBigUint::to_biguint(&bit_vec)
    }

    fn bitwise_and(input1: &Self, input2: &Self, bytes: usize) -> Self {
        let in1 = to_padded_bytes(input1, bytes);
        let in2 = to_padded_bytes(input2, bytes);
        Self::from_bytes_le(
            &in1.iter()
                .zip(in2.iter())
                .map(|(b1, b2)| b1 & b2)
                .collect::<Vec<u8>>(),
        )
    }
}

// Returns a BigUint as a Vec<u8> padded with zeros to a certain number of bytes
// Panics if bytes < input.len()
fn to_padded_bytes(input: &BigUint, bytes: usize) -> Vec<u8> {
    let bytes_inp = input.to_bytes_le().len();
    match bytes.cmp(&bytes_inp) {
        Ordering::Greater => pad(input, bytes - bytes_inp),
        Ordering::Equal | Ordering::Less => input.to_bytes_le(),
    }
}

// Pads an input with a number of bytes
fn pad(input: &BigUint, bytes: usize) -> Vec<u8> {
    let mut padded = input.to_bytes_le();
    padded.resize(bytes + padded.len(), 0u8);
    padded
}

// Returns the bit value of a BigUint input at a certain position or zero
fn bit_at(input: &BigUint, index: u32) -> bool {
    if input.bit(u64::from(index)) {
        ((input / BigUint::from(2u8).pow(index)) % BigUint::from(2u32)) == BigUint::from(1u32)
    } else {
        false
    }
}

/// Converts types to a `BigUint`
trait ToBigUint {
    /// Converts a vector of bits in little endian to a `BigUint`
    fn to_biguint(&self) -> BigUint;
}

impl ToBigUint for Vec<bool> {
    fn to_biguint(&self) -> BigUint {
        let mut bigvalue = BigUint::from(0u8);
        let mut power = BigUint::from(1u8);
        for bit in self {
            bigvalue += power.clone() * BigUint::from(u8::from(*bit));
            power *= BigUint::from(2u8);
        }
        bigvalue
    }
}
