//! This module provides a set of functions to perform bit operations on big integers.
//! In particular, it gives XOR and NOT for BigUint.
use num_bigint::BigUint;
use rand::Rng;
use std::cmp::Ordering;

/// Exclusive or of the bits of two inputs
pub trait BitOps<Rhs = Self> {
    /// Exclusive or of the bits of two BigUint inputs
    fn bitxor(input1: &Rhs, input: &Rhs) -> Rhs;

    /// Conjunction of the bits of two BigUint inputs for a given number of bytes
    fn bitand(input1: &Rhs, input: &Rhs, bytes: usize) -> Rhs;
}

impl BitOps for BigUint {
    fn bitxor(input1: &BigUint, input2: &BigUint) -> BigUint {
        // Pad to equal size in bytes
        let bytes1 = input1.to_bytes_le().len();
        let bytes2 = input2.to_bytes_le().len();
        let in1 = vectorize(input1, bytes2);
        let in2 = vectorize(input2, bytes1);
        BigUint::from_bytes_le(
            &in1.iter()
                .zip(in2.iter())
                .map(|(b1, b2)| b1 ^ b2)
                .collect::<Vec<u8>>(),
        )
    }

    fn bitand(input1: &BigUint, input2: &BigUint, bytes: usize) -> BigUint {
        let in1 = vectorize(input1, bytes);
        let in2 = vectorize(input2, bytes);
        BigUint::from_bytes_le(
            &in1.iter()
                .zip(in2.iter())
                .map(|(b1, b2)| b1 & b2)
                .collect::<Vec<u8>>(),
        )
    }
}

/// returns the minimum number of bits required to represent a BigUint
pub fn big_bits(input: &BigUint) -> usize {
    if input.to_bytes_le() == [0u8] {
        1
    } else {
        input.bits() as usize
    }
}

/// Produces a random BigUint of a given number of bits
pub fn big_random(bits: usize) -> BigUint {
    if bits == 0 {
        panic!("Cannot generate a random number of 0 bits");
    }
    let bytes = bits / 8;
    let extra = bits % 8;
    let mut big = (0..bytes)
        .map(|_| rand::thread_rng().gen_range(0..255))
        .collect::<Vec<u8>>();
    if extra > 0 {
        big.push(rand::thread_rng().gen_range(0..2u8.pow(extra as u32)));
    }
    BigUint::from_bytes_le(&big)
}

// Returns a BigUint as a Vec<u8> padded with zeros to a certain number of bytes
// Panics if bytes < input.len()
fn vectorize(input: &BigUint, bytes: usize) -> Vec<u8> {
    let bytes_inp = input.to_bytes_le().len();
    match bytes.cmp(&bytes_inp) {
        Ordering::Greater => pad(input, bytes - bytes_inp),
        Ordering::Equal | Ordering::Less => input.to_bytes_le(),
    }
}

// Pads an input with a number of bytes
fn pad(input: &BigUint, bytes: usize) -> Vec<u8> {
    let mut padded = input.to_bytes_le().to_vec();
    padded.resize(bytes + padded.len(), 0u8);
    padded
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_xor_256bits() {
        let input1: Vec<u8> = vec![
            123, 18, 7, 249, 123, 134, 183, 124, 11, 37, 29, 2, 76, 29, 3, 1, 100, 101, 102, 103,
            104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 200, 201, 202, 203, 204,
            205, 206, 207, 208, 209, 210, 211, 212, 213, 214, 215,
        ];
        let input2: Vec<u8> = vec![
            33, 76, 13, 224, 2, 0, 21, 96, 131, 137, 229, 200, 128, 255, 127, 15, 1, 2, 3, 4, 5, 6,
            7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 80, 81, 82, 93, 94, 95, 76, 77, 78, 69, 60, 61,
            52, 53, 54, 45,
        ];
        let output: Vec<u8> = vec![
            90, 94, 10, 25, 121, 134, 162, 28, 136, 172, 248, 202, 204, 226, 124, 14, 101, 103,
            101, 99, 109, 111, 109, 99, 101, 103, 101, 99, 125, 127, 125, 99, 152, 152, 152, 150,
            146, 146, 130, 130, 158, 148, 238, 238, 224, 224, 224, 250,
        ];
        let big1 = BigUint::from_bytes_le(&input1);
        let big2 = BigUint::from_bytes_le(&input2);
        assert_eq!(
            BigUint::bitxor(&big1, &big2),
            BigUint::from_bytes_le(&output)
        );
    }

    #[test]
    fn test_and_256bits() {
        let input1: Vec<u8> = vec![
            123, 18, 7, 249, 123, 134, 183, 124, 11, 37, 29, 2, 76, 29, 3, 1, 100, 101, 102, 103,
            104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 200, 201, 202, 203, 204,
            205, 206, 207, 208, 209, 210, 211, 212, 213, 214, 215,
        ];
        let input2: Vec<u8> = vec![
            33, 76, 13, 224, 2, 0, 21, 96, 131, 137, 229, 200, 128, 255, 127, 15, 1, 2, 3, 4, 5, 6,
            7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 80, 81, 82, 93, 94, 95, 76, 77, 78, 69, 60, 61,
            52, 53, 54, 45,
        ];
        let output: Vec<u8> = vec![
            33, 0, 5, 224, 2, 0, 21, 96, 3, 1, 5, 0, 0, 29, 3, 1, 0, 0, 2, 4, 0, 0, 2, 8, 8, 8, 10,
            12, 0, 0, 2, 16, 64, 65, 66, 73, 76, 77, 76, 77, 64, 65, 16, 17, 20, 21, 22, 5,
        ];
        assert_eq!(
            BigUint::bitand(
                &BigUint::from_bytes_le(&input1),
                &BigUint::from_bytes_le(&input2),
                256,
            ),
            BigUint::from_bytes_le(&output)
        );
    }

    #[test]
    fn test_xor_all_byte() {
        for byte1 in 0..256 {
            for byte2 in 0..256 {
                let input1 = BigUint::from(byte1 as u8);
                let input2 = BigUint::from(byte2 as u8);
                assert_eq!(
                    BigUint::bitxor(&input1, &input2),
                    BigUint::from((byte1 ^ byte2) as u8)
                );
            }
        }
    }
}
