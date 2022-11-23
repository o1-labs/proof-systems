//! This module provides a set of functions to perform bit operations on big integers.
//! In particular, it gives XOR and NOT for BigUint.
use num_bigint::BigUint;
use rand::Rng;
<<<<<<< HEAD
use std::cmp::{max, Ordering};

/// Exclusive or of the bits of two BigUint inputs
pub fn big_xor(input1: &BigUint, input2: &BigUint) -> BigUint {
    // Pad to equal size in bytes
    let bytes1 = input1.to_bytes_le().len();
    let bytes2 = input2.to_bytes_le().len();
    let in1 = vectorize(input1, bytes2);
    let in2 = vectorize(input2, bytes1);
=======
use std::cmp::max;

/// Exclusive or of the bits of two BigUint inputs
pub fn big_xor(input1: &BigUint, input2: &BigUint) -> BigUint {
    let bytes1 = input1.to_bytes_le().len();
    let bytes2 = input2.to_bytes_le().len();
    let in2 = if bytes1 > bytes2 {
        pad(input2, bytes1 - bytes2)
    } else {
        input2.to_bytes_le()
    };
    let in1 = if bytes2 > bytes1 {
        pad(input1, bytes2 - bytes1)
    } else {
        input1.to_bytes_le()
    };
>>>>>>> 812baa88f807f1a3806c8b2e01367181bf842ebb
    BigUint::from_bytes_le(
        &in1.iter()
            .zip(in2.iter())
            .map(|(b1, b2)| b1 ^ b2)
            .collect::<Vec<u8>>(),
    )
}

<<<<<<< HEAD
/// Conjunction of the bits of two BigUint inputs for a given number of bytes
pub fn big_and(input1: &BigUint, input2: &BigUint, bytes: usize) -> BigUint {
    let in1 = vectorize(input1, bytes);
    let in2 = vectorize(input2, bytes);
    BigUint::from_bytes_le(
        &in1.iter()
            .zip(in2.iter())
            .map(|(b1, b2)| b1 & b2)
            .collect::<Vec<u8>>(),
    )
}

=======
>>>>>>> 812baa88f807f1a3806c8b2e01367181bf842ebb
/// returns the minimum number of bits required to represent a BigUint
pub fn big_bits(input: &BigUint) -> u32 {
    if input.to_bytes_le() == [0u8] {
        1u32
    } else {
        input.bits() as u32
    }
}

/// Negate the bits of a BigUint input
/// If it provides a larger desired `bits` than the input length then it takes the padded input of `bits` length.
/// Otherwise it only takes the bits of the input.
pub fn big_not(input: &BigUint, bits: Option<u32>) -> BigUint {
    // pad if needed / desired
    // first get the number of bits of the input,
    // take into account that BigUint::bits() returns 0 if the input is 0
    let in_bits = big_bits(input) as usize;
    let bits = max(in_bits, bits.unwrap_or(0) as usize);
    // build vector of bits in little endian (least significant bit in position 0)
    let mut bit_vec = vec![];
    // negate each of the bits of the input
    (0..bits).for_each(|i| bit_vec.push(!bit_at(input, i as u32)));
    le_bitvec_to_biguint(&bit_vec)
}

/// Produces a random BigUint of a given number of bits
pub fn big_random(bits: u32) -> BigUint {
    if bits == 0 {
        panic!("Cannot generate a random number of 0 bits");
    }
    let bytes = bits / 8;
    let extra = bits % 8;
    let mut big = (0..bytes)
        .map(|_| rand::thread_rng().gen_range(0..255))
        .collect::<Vec<u8>>();
    if extra > 0 {
        big.push(rand::thread_rng().gen_range(0..2u8.pow(extra)));
    }
    BigUint::from_bytes_le(&big)
}

// Returns the bit value of a BigUint input at a certain position or zero
fn bit_at(input: &BigUint, index: u32) -> bool {
    if input.bit(index as u64) {
        ((input / BigUint::from(2u8).pow(index)) % BigUint::from(2u32)) == BigUint::from(1u32)
    } else {
        false
    }
}

<<<<<<< HEAD
// Returns a BigUint as a Vec<u8> padded with zeros to a certain number of bytes
// Panics if bytes < input.len()
fn vectorize(input: &BigUint, bytes: usize) -> Vec<u8> {
    let bytes_inp = input.to_bytes_le().len();
    match bytes.cmp(&bytes_inp) {
        Ordering::Greater => pad(input, bytes - bytes_inp),
        Ordering::Equal => input.to_bytes_le(),
        Ordering::Less => panic!("Desired length of the input is smaller than the length"),
    }
}

=======
>>>>>>> 812baa88f807f1a3806c8b2e01367181bf842ebb
// Pads an input with a number of bytes
fn pad(input: &BigUint, bytes: usize) -> Vec<u8> {
    let mut padded = input.to_bytes_le().to_vec();
    padded.resize(bytes + padded.len(), 0u8);
    padded
}

// Transforms a vector of bits in little endian to a BigUint
fn le_bitvec_to_biguint(input: &[bool]) -> BigUint {
    let mut bigvalue = BigUint::from(0u8);
    let mut power = BigUint::from(1u8);
    for bit in input {
        bigvalue += power.clone() * BigUint::from(*bit as u8);
        power *= BigUint::from(2u8);
    }
    bigvalue
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
        assert_eq!(
            big_xor(
                &BigUint::from_bytes_le(&input1),
                &BigUint::from_bytes_le(&input2)
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
                    big_xor(&input1, &input2),
                    BigUint::from((byte1 ^ byte2) as u8)
                );
            }
        }
    }

    #[test]
    fn test_not_all_byte() {
        for byte in 0..256 {
            let input = BigUint::from(byte as u8);
            let negated = BigUint::from(!byte as u8); // full 8 bits
            assert_eq!(big_not(&input, Some(8)), negated); // full byte
            let bits = big_bits(&input);
            let min_negated = 2u32.pow(bits) - 1 - byte;
            assert_eq!(big_not(&input, None), BigUint::from(min_negated)); // only up to needed
        }
    }
}
