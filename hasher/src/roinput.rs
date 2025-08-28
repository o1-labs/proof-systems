//! Random oracle input structures and algorithms
//!
//! Definition of random oracle input structure and
//! methods for serializing into bytes and field elements

use core::fmt::Error;

use super::Hashable;
use alloc::{vec, vec::Vec};
use ark_ff::{BigInteger, PrimeField};
use bitvec::{prelude::*, view::AsBits};
use mina_curves::pasta::{Fp, Fq};
use o1_utils::FieldHelpers;

/// Total number of bytes for the header of the serialized ROInput
const SER_HEADER_SIZE: usize = 8;
/// Number of bytes for each part of the header of the serialized ROInput
const SINGLE_HEADER_SIZE: usize = 4;

/// Random oracle input structure
///
/// The random oracle input encapsulates the serialization format and methods
/// using during hashing.
///
/// When implementing the [`Hashable`] trait to enable hashing for a type, you
/// must implement its `to_roinput()` serialization method using the [`ROInput`]
/// functions below.
///
/// The random oracle input structure is used (by generic code) to serialize the
/// object into both a vector of `pasta::Fp` field elements and into a vector of
/// bytes, depending on the situation.
///
/// Here is an example of how `ROInput` is used during the definition of the
/// `Hashable` trait.
///
/// ```rust
/// use mina_hasher::{Hashable, ROInput};
/// use mina_curves::pasta::Fp;
///
/// #[derive(Clone)]
/// pub struct MyExample {
///     pub x: Fp,
///     pub y: Fp,
///     pub nonce: u64,
/// }
///
/// impl Hashable for MyExample {
///     type D = ();
///
///     fn to_roinput(&self) -> ROInput {
///         ROInput::new()
///             .append_field(self.x)
///             .append_field(self.y)
///             .append_u64(self.nonce)
///     }
///
///     fn domain_string(_: Self::D) -> Option<String> {
///         format!("MyExampleMainnet").into()
///     }
/// }
/// ```
/// **Details:** For technical reasons related to our proof system and
/// performance, non-field-element members are serialized for signing
/// differently than other types. Additionally, during signing all members of
/// the random oracle input get serialized together in two different ways: both
/// as *bytes* and as a vector of *field elements*. The random oracle input
/// automates and encapsulates this complexity.
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct ROInput {
    fields: Vec<Fp>,
    bits: BitVec<u8>,
}

impl ROInput {
    /// Create a new empty random oracle input
    pub fn new() -> Self {
        ROInput {
            fields: vec![],
            bits: BitVec::new(),
        }
    }

    /// Append a `Hashable` input
    pub fn append_hashable(self, input: &impl Hashable) -> Self {
        self.append_roinput(input.to_roinput())
    }

    /// Append another random oracle input
    pub fn append_roinput(mut self, mut roi: ROInput) -> Self {
        self.fields.append(&mut roi.fields);
        self.bits.extend(roi.bits);
        self
    }

    /// Append a base field element
    pub fn append_field(mut self, f: Fp) -> Self {
        self.fields.push(f);
        self
    }

    /// Append a scalar field element by converting it to bits.
    ///
    /// This method converts the scalar field element to its byte representation,
    /// then extracts exactly [`Fq::MODULUS_BIT_SIZE`] bits (255 bits for Pallas curve)
    /// in little-endian bit order and appends them to the bits vector.
    ///
    /// # Bit Representation
    ///
    /// - Uses little-endian bit ordering within bytes (LSB first)
    /// - Extracts exactly 255 bits from the 32-byte scalar representation
    /// - The scalar field modulus is 255 bits, so the MSB of the 32nd byte is unused
    ///
    /// # Differences from [`Self::append_field`]
    ///
    /// - [`Self::append_scalar`]: Converts scalar to 255 bits and adds to the `bits` vector
    /// - [`Self::append_field`]: Adds base field element directly to the `fields` vector
    ///
    /// # Examples
    ///
    /// ```rust
    /// use mina_hasher::ROInput;
    /// use mina_curves::pasta::Fq;
    ///
    /// // Regular scalar value
    /// let scalar = Fq::from(42u64);
    /// let roi = ROInput::new().append_scalar(scalar);
    /// let bytes = roi.to_bytes();
    /// assert_eq!(bytes.len(), 32); // 255 bits rounded up to 32 bytes
    ///
    /// // Maximum scalar value (modulus - 1)
    /// let max_scalar = Fq::from(0u64) - Fq::from(1u64);
    /// let roi = ROInput::new().append_scalar(max_scalar);
    /// let bytes = roi.to_bytes();
    /// assert_eq!(bytes.len(), 32); // 255 bits rounded up to 32 bytes
    /// ```
    ///
    /// # Note
    ///
    /// All scalar field values, including the maximum value (modulus - 1),
    /// will fit exactly in 255 bits and can be safely appended.
    pub fn append_scalar(mut self, s: Fq) -> Self {
        // mina scalars are 255 bits
        let bytes = s.to_bytes();
        let bits = &bytes.as_bits::<Lsb0>()[..Fq::MODULUS_BIT_SIZE as usize];
        self.bits.extend(bits);
        self
    }

    /// Append a single bit
    pub fn append_bool(mut self, b: bool) -> Self {
        self.bits.push(b);
        self
    }

    /// Append bytes
    pub fn append_bytes(mut self, bytes: &[u8]) -> Self {
        self.bits.extend_from_bitslice(bytes.as_bits::<Lsb0>());
        self
    }

    /// Append a 32-bit unsigned integer
    pub fn append_u32(self, x: u32) -> Self {
        self.append_bytes(&x.to_le_bytes())
    }

    /// Append a 64-bit unsigned integer
    pub fn append_u64(self, x: u64) -> Self {
        self.append_bytes(&x.to_le_bytes())
    }

    /// Convert the random oracle input to a vector of packed field elements
    /// by packing the bits into field elements and appending them to the fields.
    /// The bits are packed by taking chunks of size `Fp::MODULUS_BIT_SIZE - 1`.
    pub fn to_packed_fields(&self) -> Vec<Fp> {
        let packed_size: usize = (Fp::MODULUS_BIT_SIZE - 1).try_into().unwrap();
        let packed_bits: Vec<Fp> = self
            .bits
            .chunks(packed_size)
            .map(|bitstring| {
                let bitstring: Vec<bool> = bitstring.iter().map(|b| *b).collect();
                Fp::from_bits(bitstring.as_slice()).expect("failed to create base field element")
            })
            .collect();

        let mut result = self.fields.clone();
        result.extend(packed_bits);
        result
    }

    /// Serialize random oracle input to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bits: BitVec<u8> = self.fields.iter().fold(BitVec::new(), |mut acc, fe| {
            acc.extend_from_bitslice(
                &fe.to_bytes().as_bits::<Lsb0>()[..Fp::MODULUS_BIT_SIZE as usize],
            );

            acc
        });

        bits.extend(&self.bits);

        bits.into()
    }

    /// Serialize random oracle input to vector of base field elements
    pub fn to_fields(&self) -> Vec<Fp> {
        let mut fields: Vec<Fp> = self.fields.clone();

        let bits_as_fields =
            self.bits
                .chunks(Fp::MODULUS_BIT_SIZE as usize - 1)
                .fold(vec![], |mut acc, chunk| {
                    // Workaround: chunk.clone() does not appear to respect
                    // the chunk's boundaries when it's not byte-aligned.
                    //
                    // That is,
                    //
                    //   let mut bv = chunk.clone().to_bitvec();
                    //   bv.resize(B::size_in_bits(), false);
                    //   fields.push(B::from_bytes(bv.into()));
                    //
                    // doesn't work.
                    //
                    // Instead we must do

                    let mut bv = BitVec::<u8>::new();
                    bv.resize(chunk.len(), false);
                    bv.clone_from_bitslice(chunk);

                    // extend to the size of a field;
                    bv.resize(Fp::MODULUS_BIT_SIZE as usize, false);

                    acc.push(
                        Fp::from_bytes(&bv.into_vec())
                            .expect("failed to create base field element"),
                    );

                    acc
                });

        fields.extend(bits_as_fields);

        fields
    }

    /// Serialize the ROInput into bytes
    pub fn serialize(&self) -> Vec<u8> {
        // 4-byte LE field count, 4-byte LE bit count, then payload
        let fields_len = self.fields.len() as u32;
        let bits_len = self.bits.len() as u32;

        let mut bytes = Vec::with_capacity(SER_HEADER_SIZE + self.to_bytes().len());
        bytes.extend_from_slice(&fields_len.to_le_bytes());
        bytes.extend_from_slice(&bits_len.to_le_bytes());
        bytes.extend_from_slice(&self.to_bytes());
        bytes
    }

    /// Deserialize a `ROInput` from bytes
    pub fn deserialize(input: &[u8]) -> Result<Self, Error> {
        if input.len() < SER_HEADER_SIZE {
            return Err(Error);
        }

        // read back our two u32 little-endian lengths
        let fields_len =
            u32::from_le_bytes(input[0..SINGLE_HEADER_SIZE].try_into().unwrap()) as usize;
        let bits_len = u32::from_le_bytes(
            input[SINGLE_HEADER_SIZE..SER_HEADER_SIZE]
                .try_into()
                .unwrap(),
        ) as usize;

        // the rest is payload
        let bits = input[SER_HEADER_SIZE..].view_bits::<Lsb0>();

        // Check that the number of bytes is consistent with the expected lengths
        let expected_len_bits = fields_len * Fp::MODULUS_BIT_SIZE as usize + bits_len;
        // Round up to nearest multiple of 8
        let expected_len = (expected_len_bits + 7) / 8 + SER_HEADER_SIZE;
        if input.len() != expected_len {
            return Err(Error);
        }

        // allocate space for exactly `fields_len` elements
        let mut fields = Vec::with_capacity(fields_len);

        for chunk in bits.chunks(Fp::MODULUS_BIT_SIZE as usize).take(fields_len) {
            let bools: Vec<bool> = chunk.iter().by_vals().collect();
            // conver little-endian bits to a big integer representation
            let repr = <Fp as PrimeField>::BigInt::from_bits_le(&bools);
            // convert to field element (reduces mod p)
            let elt = Fp::from_bigint(repr).ok_or(Error)?;
            fields.push(elt);
        }

        let remainder = &bits[fields_len * Fp::MODULUS_BIT_SIZE as usize..];
        // Delete the final bits according to the bits length
        let bits = remainder.iter().take(bits_len).collect::<BitVec<u8>>();

        let roi = ROInput { fields, bits };

        Ok(roi)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        alloc::string::{String, ToString},
        Hashable,
    };

    #[test]
    fn append_bool() {
        let roi = ROInput::new().append_bool(true);
        assert!(roi.bits.len() == 1);
        assert!(roi.bits.as_raw_slice() == [0x01]);
    }

    #[test]
    fn append_two_bits() {
        let roi = ROInput::new().append_bool(false).append_bool(true);
        assert!(roi.bits.len() == 2);
        assert!(roi.bits.as_raw_slice() == [0x02]);
    }

    #[test]
    fn append_five_bits() {
        let roi = ROInput::new()
            .append_bool(false)
            .append_bool(true)
            .append_bool(false)
            .append_bool(false)
            .append_bool(true);
        assert!(roi.bits.len() == 5);
        assert!(roi.bits.as_raw_slice() == [0x12]);
    }

    #[test]
    fn append_byte() {
        let roi = ROInput::new().append_bytes(&[0x01]);
        assert!(roi.bits.len() == 8);
        assert!(roi.bits.as_raw_slice() == [0x01]);
    }

    #[test]
    fn append_two_bytes() {
        let roi = ROInput::new().append_bytes(&[0x10, 0xac]);
        assert!(roi.bits.len() == 16);
        assert!(roi.bits.as_raw_slice() == [0x10, 0xac]);
    }

    #[test]
    fn append_five_bytes() {
        let roi = ROInput::new().append_bytes(&[0x10, 0xac, 0x01, 0xeb, 0xca]);
        assert!(roi.bits.len() == 40);
        assert!(roi.bits.as_raw_slice() == [0x10, 0xac, 0x01, 0xeb, 0xca]);
    }

    #[test]
    fn append_scalar() {
        let scalar =
            Fq::from_hex("18b7ef420128e69623c0c0dcfa28d47a029d462720deb769d7b5dd6f17444216")
                .expect("failed to create scalar");
        let roi = ROInput::new().append_scalar(scalar);
        assert_eq!(roi.bits.len(), 255);
        assert_eq!(
            roi.bits.as_raw_slice(),
            [
                0x18, 0xb7, 0xef, 0x42, 0x01, 0x28, 0xe6, 0x96, 0x23, 0xc0, 0xc0, 0xdc, 0xfa, 0x28,
                0xd4, 0x7a, 0x02, 0x9d, 0x46, 0x27, 0x20, 0xde, 0xb7, 0x69, 0xd7, 0xb5, 0xdd, 0x6f,
                0x17, 0x44, 0x42, 0x16
            ]
        );
        assert_eq!(
            roi.to_bytes(),
            [
                0x18, 0xb7, 0xef, 0x42, 0x01, 0x28, 0xe6, 0x96, 0x23, 0xc0, 0xc0, 0xdc, 0xfa, 0x28,
                0xd4, 0x7a, 0x02, 0x9d, 0x46, 0x27, 0x20, 0xde, 0xb7, 0x69, 0xd7, 0xb5, 0xdd, 0x6f,
                0x17, 0x44, 0x42, 0x16
            ]
        );
    }

    #[test]
    fn append_scalar_and_byte() {
        let scalar =
            Fq::from_hex("18b7ef420128e69623c0c0dcfa28d47a029d462720deb769d7b5dd6f17444216")
                .expect("failed to create scalar");
        let roi = ROInput::new().append_scalar(scalar).append_bytes(&[0x01]);
        assert!(roi.bits.len() == 263);
        assert!(
            roi.bits.as_raw_slice()
                == [
                    0x18, 0xb7, 0xef, 0x42, 0x01, 0x28, 0xe6, 0x96, 0x23, 0xc0, 0xc0, 0xdc, 0xfa,
                    0x28, 0xd4, 0x7a, 0x02, 0x9d, 0x46, 0x27, 0x20, 0xde, 0xb7, 0x69, 0xd7, 0xb5,
                    0xdd, 0x6f, 0x17, 0x44, 0x42, 0x96, 0x00
                ]
        );
    }

    #[test]
    fn append_two_scalars() {
        let scalar1 =
            Fq::from_hex("18b7ef420128e69623c0c0dcfa28d47a029d462720deb769d7b5dd6f17444216")
                .expect("failed to create scalar");
        let scalar2 =
            Fq::from_hex("a1b1e948835be341277548134e0effabdbcb95b742e8c5e967e9bf13eb4ae805")
                .expect("failed to create scalar");
        let roi = ROInput::new().append_scalar(scalar1).append_scalar(scalar2);
        assert!(roi.bits.len() == 510);
        assert!(
            roi.bits.as_raw_slice()
                == [
                    0x18, 0xb7, 0xef, 0x42, 0x01, 0x28, 0xe6, 0x96, 0x23, 0xc0, 0xc0, 0xdc, 0xfa,
                    0x28, 0xd4, 0x7a, 0x02, 0x9d, 0x46, 0x27, 0x20, 0xde, 0xb7, 0x69, 0xd7, 0xb5,
                    0xdd, 0x6f, 0x17, 0x44, 0x42, 0x96, 0xd0, 0xd8, 0x74, 0xa4, 0xc1, 0xad, 0xf1,
                    0xa0, 0x93, 0x3a, 0xa4, 0x09, 0x27, 0x87, 0xff, 0xd5, 0xed, 0xe5, 0xca, 0x5b,
                    0x21, 0xf4, 0xe2, 0xf4, 0xb3, 0xf4, 0xdf, 0x89, 0x75, 0x25, 0xf4, 0x02
                ]
        );
    }

    #[test]
    fn append_two_scalars_and_byte() {
        let scalar1 =
            Fq::from_hex("60db6f4f5b8ce1c7cb747fba9e324cc3268c7a6e3f43cd82d451ae99a7b2bd1f")
                .expect("failed to create scalar");
        let scalar2 =
            Fq::from_hex("fe7775b106bceb58f3e23e5a4eb99f404b8ed8cf2afeef9c9d1800f12138cd07")
                .expect("failed to create scalar");
        let roi = ROInput::new()
            .append_scalar(scalar1)
            .append_bytes(&[0x2a])
            .append_scalar(scalar2);
        assert!(roi.bits.len() == 518);
        assert!(
            roi.bits.as_raw_slice()
                == [
                    0x60, 0xdb, 0x6f, 0x4f, 0x5b, 0x8c, 0xe1, 0xc7, 0xcb, 0x74, 0x7f, 0xba, 0x9e,
                    0x32, 0x4c, 0xc3, 0x26, 0x8c, 0x7a, 0x6e, 0x3f, 0x43, 0xcd, 0x82, 0xd4, 0x51,
                    0xae, 0x99, 0xa7, 0xb2, 0xbd, 0x1f, 0x15, 0xff, 0xbb, 0xba, 0x58, 0x03, 0xde,
                    0x75, 0xac, 0x79, 0x71, 0x1f, 0x2d, 0xa7, 0xdc, 0x4f, 0xa0, 0x25, 0x47, 0xec,
                    0x67, 0x15, 0xff, 0x77, 0xce, 0x4e, 0x0c, 0x80, 0xf8, 0x10, 0x9c, 0xe6, 0x03
                ]
        );
    }

    #[test]
    fn test_append_scalar_max_value() {
        // Test with the maximum scalar field value (modulus - 1)
        let max_scalar = Fq::from(0u64) - Fq::from(1u64); // Fq modulus - 1
        let roi = ROInput::new().append_scalar(max_scalar);

        // Should add 255 bits (Fq::MODULUS_BIT_SIZE)
        assert_eq!(roi.bits.len(), 255);
        assert_eq!(roi.fields.len(), 0);

        // Verify the bits represent the maximum scalar value
        let reconstructed_bytes = roi.bits.as_raw_slice();
        let expected_bytes = max_scalar.to_bytes();

        // Compare the first 31 bytes (255 bits = 31 bytes + 7 bits)
        assert_eq!(&reconstructed_bytes[..31], &expected_bytes[..31]);

        // Check the last partial byte (7 bits from the 32nd byte)
        let last_byte_mask = 0x7F; // Mask for 7 bits: 0111_1111
        assert_eq!(
            reconstructed_bytes[31] & last_byte_mask,
            expected_bytes[31] & last_byte_mask
        );

        // Test serialization to bytes
        let serialized_bytes = roi.to_bytes();
        assert_eq!(serialized_bytes.len(), 32); // 255 bits rounded up to 32 bytes

        // Test that max scalar converts to proper field elements
        let fields = roi.to_fields();
        assert_eq!(fields.len(), 2); // Should pack into 2 field elements

        // Verify we can append multiple max scalars
        let roi_double = ROInput::new()
            .append_scalar(max_scalar)
            .append_scalar(max_scalar);
        assert_eq!(roi_double.bits.len(), 510); // 2 * 255 bits

        let fields_double = roi_double.to_fields();
        assert_eq!(fields_double.len(), 3); // Should pack into 3 field elements
    }

    #[test]
    fn append_u32() {
        let roi = ROInput::new().append_u32(1984u32);
        assert!(roi.bits.len() == 32);
        assert!(roi.bits.as_raw_slice() == [0xc0, 0x07, 0x00, 0x00]);
    }

    #[test]
    fn append_two_u32_and_bit() {
        let roi = ROInput::new()
            .append_u32(1729u32)
            .append_bool(false)
            .append_u32(u32::MAX);
        assert!(roi.bits.len() == 65);
        assert!(roi.bits.as_raw_slice() == [0xc1, 0x06, 0x00, 0x00, 0xfe, 0xff, 0xff, 0xff, 0x01]);
    }

    #[test]
    fn append_u64() {
        let roi = ROInput::new().append_u64(6174u64);
        assert!(roi.bits.len() == 64);
        assert!(roi.bits.as_raw_slice() == [0x1e, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn append_two_u64_and_bits() {
        let roi = ROInput::new()
            .append_bool(true)
            .append_u64(u64::MAX / 6174u64)
            .append_bool(false)
            .append_u64(u64::MAX / 1111u64);
        assert!(roi.bits.len() == 130);
        assert!(
            roi.bits.as_raw_slice()
                == [
                    0xe1, 0x29, 0x89, 0xd6, 0xcb, 0x3a, 0x15, 0x00, 0x08, 0x17, 0xc4, 0x9b, 0x04,
                    0xf4, 0xeb, 0x00, 0x00
                ]
        );
    }

    #[test]
    fn all_1() {
        let roi = ROInput::new()
            .append_bool(true)
            .append_scalar(
                Fq::from_hex("01d1755db21c8cd2a9cf5a3436178da3d70f484cd4b4c8834b799921e7d7a102")
                    .expect("failed to create scalar"),
            )
            .append_u64(18446744073709551557)
            .append_bytes(&[0xba, 0xdc, 0x0f, 0xfe])
            .append_scalar(
                Fq::from_hex("e70187e9b125524489d0433da76fd8287fa652eaebde147b45fa0cd86f171810")
                    .expect("failed to create scalar"),
            )
            .append_bool(false)
            .append_u32(2147483647)
            .append_bool(true);

        assert!(roi.bits.len() == 641);
        assert!(
            roi.bits.as_raw_slice()
                == [
                    0x03, 0xa2, 0xeb, 0xba, 0x64, 0x39, 0x18, 0xa5, 0x53, 0x9f, 0xb5, 0x68, 0x6c,
                    0x2e, 0x1a, 0x47, 0xaf, 0x1f, 0x90, 0x98, 0xa8, 0x69, 0x91, 0x07, 0x97, 0xf2,
                    0x32, 0x43, 0xce, 0xaf, 0x43, 0x05, 0xc5, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xba, 0xdc, 0x0f, 0xfe, 0xe7, 0x01, 0x87, 0xe9, 0xb1, 0x25, 0x52, 0x44,
                    0x89, 0xd0, 0x43, 0x3d, 0xa7, 0x6f, 0xd8, 0x28, 0x7f, 0xa6, 0x52, 0xea, 0xeb,
                    0xde, 0x14, 0x7b, 0x45, 0xfa, 0x0c, 0xd8, 0x6f, 0x17, 0x18, 0x10, 0xff, 0xff,
                    0xff, 0x7f, 0x01
                ]
        );
    }

    #[test]
    fn transaction_bits() {
        let roi = ROInput::new()
            .append_u64(1000000) // fee
            .append_u64(1) // fee token
            .append_bool(true) // fee payer pk odd
            .append_u32(0) // nonce
            .append_u32(u32::MAX) // valid_until
            .append_bytes(&[0; 34]) // memo
            .append_bool(false) // tags[0]
            .append_bool(false) // tags[1]
            .append_bool(false) // tags[2]
            .append_bool(true) // sender pk odd
            .append_bool(false) // receiver pk odd
            .append_u64(1) // token_id
            .append_u64(10000000000) // amount
            .append_bool(false) // token_locked
            .append_scalar(
                Fq::from_hex("de217a3017ca0b7a278e75f63c09890e3894be532d8dbadd30a7d450055f6d2d")
                    .expect("failed to create scalar"),
            )
            .append_bytes(&[0x01]);
        assert_eq!(roi.bits.len(), 862);
        assert_eq!(
            roi.bits.as_raw_slice(),
            [
                0x40, 0x42, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0xfe, 0xff, 0xff, 0xff, 0x01, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf9, 0x02,
                0x95, 0x00, 0x00, 0x00, 0x00, 0xef, 0x10, 0x3d, 0x98, 0x0b, 0xe5, 0x05, 0xbd, 0x13,
                0xc7, 0x3a, 0x7b, 0x9e, 0x84, 0x44, 0x07, 0x1c, 0x4a, 0xdf, 0xa9, 0x96, 0x46, 0xdd,
                0x6e, 0x98, 0x53, 0x6a, 0xa8, 0x82, 0xaf, 0xb6, 0x56, 0x00
            ]
        )
    }

    #[test]
    fn append_field() {
        let roi = ROInput::new().append_field(
            Fp::from_hex("2eaedae42a7461d5952d27b97ecad068b698ebb94e8a0e4c45388bb613de7e08")
                .expect("failed to create field"),
        );

        assert_eq!(
            roi.to_bytes(),
            [
                0x2e, 0xae, 0xda, 0xe4, 0x2a, 0x74, 0x61, 0xd5, 0x95, 0x2d, 0x27, 0xb9, 0x7e, 0xca,
                0xd0, 0x68, 0xb6, 0x98, 0xeb, 0xb9, 0x4e, 0x8a, 0x0e, 0x4c, 0x45, 0x38, 0x8b, 0xb6,
                0x13, 0xde, 0x7e, 0x08
            ]
        );
    }

    #[test]
    fn append_two_fields() {
        let roi = ROInput::new()
            .append_field(
                Fp::from_hex("0cdaf334e9632268a5aa959c2781fb32bf45565fe244ae42c849d3fdc7c6441d")
                    .expect("failed to create field"),
            )
            .append_field(
                Fp::from_hex("2eaedae42a7461d5952d27b97ecad068b698ebb94e8a0e4c45388bb613de7e08")
                    .expect("failed to create field"),
            );

        assert_eq!(
            roi.to_bytes(),
            [
                0x0c, 0xda, 0xf3, 0x34, 0xe9, 0x63, 0x22, 0x68, 0xa5, 0xaa, 0x95, 0x9c, 0x27, 0x81,
                0xfb, 0x32, 0xbf, 0x45, 0x56, 0x5f, 0xe2, 0x44, 0xae, 0x42, 0xc8, 0x49, 0xd3, 0xfd,
                0xc7, 0xc6, 0x44, 0x1d, 0x17, 0x57, 0x6d, 0x72, 0x15, 0xba, 0xb0, 0xea, 0xca, 0x96,
                0x93, 0x5c, 0x3f, 0x65, 0x68, 0x34, 0x5b, 0xcc, 0xf5, 0x5c, 0x27, 0x45, 0x07, 0xa6,
                0x22, 0x9c, 0x45, 0xdb, 0x09, 0x6f, 0x3f, 0x04
            ]
        );
    }

    #[test]
    fn append_three_fields() {
        let roi = ROInput::new()
            .append_field(
                Fp::from_hex("1f3f142986041b54427aa2032632e34df2fa9bde9bce70c04c5034266619e529")
                    .expect("failed to create field"),
            )
            .append_field(
                Fp::from_hex("37f4433b85e753a91a1d79751645f1448954c433f9492e36a933ca7f3df61a04")
                    .expect("failed to create field"),
            )
            .append_field(
                Fp::from_hex("6cf4772d3e1aab98a2b514b73a4f6e0df1fb4f703ecfa762196b22c26da4341c")
                    .expect("failed to create field"),
            );

        assert_eq!(
            roi.to_bytes(),
            [
                0x1f, 0x3f, 0x14, 0x29, 0x86, 0x04, 0x1b, 0x54, 0x42, 0x7a, 0xa2, 0x03, 0x26, 0x32,
                0xe3, 0x4d, 0xf2, 0xfa, 0x9b, 0xde, 0x9b, 0xce, 0x70, 0xc0, 0x4c, 0x50, 0x34, 0x26,
                0x66, 0x19, 0xe5, 0xa9, 0x1b, 0xfa, 0xa1, 0x9d, 0xc2, 0xf3, 0xa9, 0x54, 0x8d, 0x8e,
                0xbc, 0x3a, 0x8b, 0xa2, 0x78, 0xa2, 0x44, 0x2a, 0xe2, 0x99, 0xfc, 0x24, 0x17, 0x9b,
                0xd4, 0x19, 0xe5, 0xbf, 0x1e, 0x7b, 0x0d, 0x02, 0x1b, 0xfd, 0x5d, 0x8b, 0x8f, 0xc6,
                0x2a, 0xa6, 0x68, 0x2d, 0xc5, 0xad, 0xce, 0x93, 0x5b, 0x43, 0xfc, 0xfe, 0x13, 0x9c,
                0xcf, 0xf3, 0xa9, 0x58, 0xc6, 0x9a, 0x88, 0x70, 0x1b, 0x29, 0x0d, 0x07
            ]
        );
    }

    #[test]
    fn append_field_and_scalar() {
        let roi = ROInput::new()
            .append_field(
                Fp::from_hex("64cde530327a36fcb88b6d769adca9b7c5d266e7d0042482203f3fd3a0d71721")
                    .expect("failed to create field"),
            )
            .append_scalar(
                Fq::from_hex("604355d0daa455db783fd7ee11c5bd9b04d67ba64c27c95bef95e379f98c6432")
                    .expect("failed to create scalar"),
            );

        assert_eq!(
            roi.to_bytes(),
            [
                0x64, 0xcd, 0xe5, 0x30, 0x32, 0x7a, 0x36, 0xfc, 0xb8, 0x8b, 0x6d, 0x76, 0x9a, 0xdc,
                0xa9, 0xb7, 0xc5, 0xd2, 0x66, 0xe7, 0xd0, 0x04, 0x24, 0x82, 0x20, 0x3f, 0x3f, 0xd3,
                0xa0, 0xd7, 0x17, 0x21, 0xb0, 0xa1, 0x2a, 0x68, 0x6d, 0xd2, 0xaa, 0x6d, 0xbc, 0x9f,
                0x6b, 0xf7, 0x88, 0xe2, 0xde, 0x4d, 0x02, 0xeb, 0x3d, 0x53, 0xa6, 0x93, 0xe4, 0xad,
                0xf7, 0xca, 0xf1, 0xbc, 0x7c, 0x46, 0x32, 0x19
            ]
        );
    }

    #[test]
    fn append_field_bit_and_scalar() {
        let roi = ROInput::new()
            .append_field(
                Fp::from_hex("d897c7a8b811d8acd3eeaa4adf42292802eed80031c2ad7c8989aea1fe94322c")
                    .expect("failed to create field"),
            )
            .append_bool(false)
            .append_scalar(
                Fq::from_hex("79586cc6b8b53c8991b2abe0ca76508f056ca50f06836ce4d818c2ff73d42b28")
                    .expect("failed to create scalar"),
            );

        assert_eq!(
            roi.to_bytes(),
            [
                0xd8, 0x97, 0xc7, 0xa8, 0xb8, 0x11, 0xd8, 0xac, 0xd3, 0xee, 0xaa, 0x4a, 0xdf, 0x42,
                0x29, 0x28, 0x02, 0xee, 0xd8, 0x00, 0x31, 0xc2, 0xad, 0x7c, 0x89, 0x89, 0xae, 0xa1,
                0xfe, 0x94, 0x32, 0x2c, 0x79, 0x58, 0x6c, 0xc6, 0xb8, 0xb5, 0x3c, 0x89, 0x91, 0xb2,
                0xab, 0xe0, 0xca, 0x76, 0x50, 0x8f, 0x05, 0x6c, 0xa5, 0x0f, 0x06, 0x83, 0x6c, 0xe4,
                0xd8, 0x18, 0xc2, 0xff, 0x73, 0xd4, 0x2b, 0x28
            ]
        );
    }

    #[test]
    fn to_bytes() {
        let roi = ROInput::new()
            .append_field(
                Fp::from_hex("a5984f2bd00906f9a86e75bfb4b2c3625f1a0d1cfacc1501e8e82ae7041efc14")
                    .expect("failed to create field"),
            )
            .append_field(
                Fp::from_hex("8af0bc770d49a5b9fcabfcdd033bab470b2a211ef80b710efe71315cfa818c0a")
                    .expect("failed to create field"),
            )
            .append_bool(false)
            .append_u32(314u32)
            .append_scalar(
                Fq::from_hex("c23c43a23ddc1516578b0f0d81b93cdbbc97744acc697cfc8c5dfd01cc448323")
                    .expect("failed to create scalar"),
            );

        assert_eq!(
            roi.to_bytes(),
            [
                0xa5, 0x98, 0x4f, 0x2b, 0xd0, 0x09, 0x06, 0xf9, 0xa8, 0x6e, 0x75, 0xbf, 0xb4, 0xb2,
                0xc3, 0x62, 0x5f, 0x1a, 0x0d, 0x1c, 0xfa, 0xcc, 0x15, 0x01, 0xe8, 0xe8, 0x2a, 0xe7,
                0x04, 0x1e, 0xfc, 0x14, 0x45, 0x78, 0xde, 0xbb, 0x86, 0xa4, 0xd2, 0x5c, 0xfe, 0x55,
                0xfe, 0xee, 0x81, 0x9d, 0xd5, 0xa3, 0x05, 0x95, 0x10, 0x0f, 0xfc, 0x85, 0x38, 0x07,
                0xff, 0xb8, 0x18, 0x2e, 0xfd, 0x40, 0x46, 0x05, 0x9d, 0x00, 0x00, 0x00, 0x61, 0x9e,
                0x21, 0xd1, 0x1e, 0xee, 0x0a, 0x8b, 0xab, 0xc5, 0x87, 0x86, 0xc0, 0x5c, 0x9e, 0x6d,
                0xde, 0x4b, 0x3a, 0x25, 0xe6, 0x34, 0x3e, 0x7e, 0xc6, 0xae, 0xfe, 0x00, 0x66, 0xa2,
                0xc1, 0x11
            ]
        );
    }

    #[test]
    fn to_fields_1_scalar() {
        let roi = ROInput::new().append_scalar(
            Fq::from_hex("5d496dd8ff63f640c006887098092b16bc8c78504f84fa1ee3a0b54f85f0a625")
                .expect("failed to create scalar"),
        );

        assert_eq!(
            roi.to_bytes(),
            [
                0x5d, 0x49, 0x6d, 0xd8, 0xff, 0x63, 0xf6, 0x40, 0xc0, 0x06, 0x88, 0x70, 0x98, 0x09,
                0x2b, 0x16, 0xbc, 0x8c, 0x78, 0x50, 0x4f, 0x84, 0xfa, 0x1e, 0xe3, 0xa0, 0xb5, 0x4f,
                0x85, 0xf0, 0xa6, 0x25
            ]
        );

        assert_eq!(
            roi.to_fields(),
            [
                Fp::from_hex("5d496dd8ff63f640c006887098092b16bc8c78504f84fa1ee3a0b54f85f0a625")
                    .expect("failed to create field"),
                Fp::from_hex("0000000000000000000000000000000000000000000000000000000000000000")
                    .expect("failed to create field"),
            ]
        );
    }

    #[test]
    fn to_fields_1_scalar_2_bits() {
        let roi = ROInput::new()
            .append_scalar(
                Fq::from_hex("e8a9961c8c417b0d0e3d7366f6b0e6ef90a6dad123070f715e8a9eaa02e47330")
                    .expect("failed to create scalar"),
            )
            .append_bool(false)
            .append_bool(true);

        assert_eq!(
            roi.to_bytes(),
            [
                0xe8, 0xa9, 0x96, 0x1c, 0x8c, 0x41, 0x7b, 0x0d, 0x0e, 0x3d, 0x73, 0x66, 0xf6, 0xb0,
                0xe6, 0xef, 0x90, 0xa6, 0xda, 0xd1, 0x23, 0x07, 0x0f, 0x71, 0x5e, 0x8a, 0x9e, 0xaa,
                0x02, 0xe4, 0x73, 0x30, 0x01
            ]
        );

        assert_eq!(
            roi.to_fields(),
            [
                Fp::from_hex("e8a9961c8c417b0d0e3d7366f6b0e6ef90a6dad123070f715e8a9eaa02e47330")
                    .expect("failed to create field"),
                Fp::from_hex("0400000000000000000000000000000000000000000000000000000000000000")
                    .expect("failed to create field"),
            ]
        );
    }

    #[test]
    fn to_fields_2_scalars() {
        let roi = ROInput::new()
            .append_scalar(
                Fq::from_hex("e05c25d2c17ec20d6bc8fd21204af52808451076cff687407164a21d352ddd22")
                    .expect("failed to create scalar"),
            )
            .append_scalar(
                Fq::from_hex("c356dbb39478508818e0320dffa6c1ef512564366ec885ee2fc4d385dd36df0f")
                    .expect("failed to create scalar"),
            );

        assert_eq!(
            roi.to_bytes(),
            [
                0xe0, 0x5c, 0x25, 0xd2, 0xc1, 0x7e, 0xc2, 0x0d, 0x6b, 0xc8, 0xfd, 0x21, 0x20, 0x4a,
                0xf5, 0x28, 0x08, 0x45, 0x10, 0x76, 0xcf, 0xf6, 0x87, 0x40, 0x71, 0x64, 0xa2, 0x1d,
                0x35, 0x2d, 0xdd, 0xa2, 0x61, 0xab, 0xed, 0x59, 0x4a, 0x3c, 0x28, 0x44, 0x0c, 0x70,
                0x99, 0x86, 0x7f, 0xd3, 0xe0, 0xf7, 0xa8, 0x12, 0x32, 0x1b, 0x37, 0xe4, 0x42, 0xf7,
                0x17, 0xe2, 0xe9, 0xc2, 0x6e, 0x9b, 0xef, 0x07
            ]
        );

        assert_eq!(
            roi.to_fields(),
            [
                Fp::from_hex("e05c25d2c17ec20d6bc8fd21204af52808451076cff687407164a21d352ddd22")
                    .expect("failed to create field"),
                Fp::from_hex("86adb66729f1a01031c0651afe4d83dfa34ac86cdc900bdd5f88a70bbb6dbe1f")
                    .expect("failed to create field"),
                Fp::from_hex("0000000000000000000000000000000000000000000000000000000000000000")
                    .expect("failed to create field"),
            ]
        );
    }

    #[test]
    fn to_fields_2_bits_scalar_u32() {
        let roi = ROInput::new()
            .append_bool(true)
            .append_bool(false)
            .append_scalar(
                Fq::from_hex("689634de233b06251a80ac7df64483922727757eea1adc6f0c8f184441cfe10d")
                    .expect("failed to create scalar"),
            )
            .append_u32(834803);

        assert_eq!(
            roi.to_bytes(),
            [
                0xa1, 0x59, 0xd2, 0x78, 0x8f, 0xec, 0x18, 0x94, 0x68, 0x00, 0xb2, 0xf6, 0xd9, 0x13,
                0x0d, 0x4a, 0x9e, 0x9c, 0xd4, 0xf9, 0xa9, 0x6b, 0x70, 0xbf, 0x31, 0x3c, 0x62, 0x10,
                0x05, 0x3d, 0x87, 0x37, 0xe6, 0x79, 0x19, 0x00, 0x00
            ]
        );

        assert_eq!(
            roi.to_fields(),
            [
                Fp::from_hex("a159d2788fec18946800b2f6d9130d4a9e9cd4f9a96b70bf313c6210053d8737")
                    .expect("failed to create field"),
                Fp::from_hex("98e7650000000000000000000000000000000000000000000000000000000000")
                    .expect("failed to create field"),
            ]
        );
    }

    #[test]
    fn to_fields_2_bits_field_scalar() {
        let roi = ROInput::new()
            .append_bool(false)
            .append_bool(true)
            .append_field(
                Fp::from_hex("90926b620ad09ed616d5df158504faed42928719c58ae619d9eccc062f920411")
                    .expect("failed to create field"),
            )
            .append_scalar(
                Fq::from_hex("689634de233b06251a80ac7df64483922727757eea1adc6f0c8f184441cfe10d")
                    .expect("failed to create scalar"),
            );

        assert_eq!(
            roi.to_bytes(),
            [
                0x90, 0x92, 0x6b, 0x62, 0x0a, 0xd0, 0x9e, 0xd6, 0x16, 0xd5, 0xdf, 0x15, 0x85, 0x04,
                0xfa, 0xed, 0x42, 0x92, 0x87, 0x19, 0xc5, 0x8a, 0xe6, 0x19, 0xd9, 0xec, 0xcc, 0x06,
                0x2f, 0x92, 0x04, 0x11, 0xd1, 0x2c, 0x69, 0xbc, 0x47, 0x76, 0x0c, 0x4a, 0x34, 0x00,
                0x59, 0xfb, 0xec, 0x89, 0x06, 0x25, 0x4f, 0x4e, 0xea, 0xfc, 0xd4, 0x35, 0xb8, 0xdf,
                0x18, 0x1e, 0x31, 0x88, 0x82, 0x9e, 0xc3, 0x1b
            ]
        );

        assert_eq!(
            roi.to_fields(),
            [
                Fp::from_hex("90926b620ad09ed616d5df158504faed42928719c58ae619d9eccc062f920411")
                    .expect("failed to create field"),
                Fp::from_hex("a259d2788fec18946800b2f6d9130d4a9e9cd4f9a96b70bf313c6210053d8737")
                    .expect("failed to create field"),
                Fp::from_hex("0000000000000000000000000000000000000000000000000000000000000000")
                    .expect("failed to create field"),
            ]
        );
    }

    #[test]
    fn transaction_test_1() {
        let roi = ROInput::new()
            .append_field(
                Fp::from_hex("41203c6bbac14b357301e1f386d80f52123fd00f02197491b690bddfa742ca22")
                    .expect("failed to create field"),
            ) // fee payer
            .append_field(
                Fp::from_hex("992cdaf29ffe15b2bcea5d00e498ed4fffd117c197f0f98586e405f72ef88e00")
                    .expect("failed to create field"),
            ) // source
            .append_field(
                Fp::from_hex("3fba4fa71bce0dfdf709d827463036d6291458dfef772ff65e87bd6d1b1e062a")
                    .expect("failed to create field"),
            ) // receiver
            .append_u64(1000000) // fee
            .append_u64(1) // fee token
            .append_bool(true) // fee payer pk odd
            .append_u32(0) // nonce
            .append_u32(u32::MAX) // valid_until
            .append_bytes(&[0; 34]) // memo
            .append_bool(false) // tags[0]
            .append_bool(false) // tags[1]
            .append_bool(false) // tags[2]
            .append_bool(true) // sender pk odd
            .append_bool(false) // receiver pk odd
            .append_u64(1) // token_id
            .append_u64(10000000000) // amount
            .append_bool(false); // token_locked
        assert_eq!(roi.bits.len() + roi.fields.len() * 255, 1364);
        assert_eq!(
            roi.to_bytes(),
            [
                0x41, 0x20, 0x3c, 0x6b, 0xba, 0xc1, 0x4b, 0x35, 0x73, 0x01, 0xe1, 0xf3, 0x86, 0xd8,
                0x0f, 0x52, 0x12, 0x3f, 0xd0, 0x0f, 0x02, 0x19, 0x74, 0x91, 0xb6, 0x90, 0xbd, 0xdf,
                0xa7, 0x42, 0xca, 0xa2, 0x4c, 0x16, 0x6d, 0xf9, 0x4f, 0xff, 0x0a, 0x59, 0x5e, 0xf5,
                0x2e, 0x00, 0x72, 0xcc, 0xf6, 0xa7, 0xff, 0xe8, 0x8b, 0xe0, 0x4b, 0xf8, 0xfc, 0x42,
                0x43, 0xf2, 0x82, 0x7b, 0x17, 0x7c, 0x47, 0xc0, 0x8f, 0xee, 0xd3, 0xe9, 0x86, 0x73,
                0x43, 0xff, 0x7d, 0x02, 0xf6, 0x89, 0x11, 0x8c, 0x8d, 0x75, 0x0a, 0x05, 0xd6, 0xf7,
                0xfb, 0xdd, 0x8b, 0xbd, 0xd7, 0x61, 0x6f, 0xdb, 0x86, 0x87, 0x81, 0x0a, 0x48, 0xe8,
                0x01, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20,
                0x00, 0x00, 0x00, 0xc0, 0xff, 0xff, 0xff, 0x3f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x5f, 0xa0, 0x12, 0x00,
                0x00, 0x00, 0x00
            ]
        );

        assert_eq!(
            roi.to_fields(),
            [
                Fp::from_hex("41203c6bbac14b357301e1f386d80f52123fd00f02197491b690bddfa742ca22")
                    .expect("failed to create field"),
                Fp::from_hex("992cdaf29ffe15b2bcea5d00e498ed4fffd117c197f0f98586e405f72ef88e00")
                    .expect("failed to create field"),
                Fp::from_hex("3fba4fa71bce0dfdf709d827463036d6291458dfef772ff65e87bd6d1b1e062a")
                    .expect("failed to create field"),
                Fp::from_hex("40420f0000000000010000000000000001000000feffffff0100000000000000")
                    .expect("failed to create field"),
                Fp::from_hex("0000000000000000000000000000000000000000000000000000400100000000")
                    .expect("failed to create field"),
                Fp::from_hex("00000000902f5009000000000000000000000000000000000000000000000000")
                    .expect("failed to create field"),
            ]
        );
    }

    #[test]
    fn nested_roinput_test() {
        #[derive(Clone, Debug)]
        struct A {
            x: u32,
            y: bool,
            z: u32,
        }

        impl Hashable for A {
            type D = ();

            fn to_roinput(&self) -> ROInput {
                ROInput::new()
                    .append_u32(self.x)
                    .append_bool(self.y)
                    .append_u32(self.z)
            }

            fn domain_string(_: Self::D) -> Option<String> {
                "A".to_string().into()
            }
        }

        #[derive(Clone, Debug)]
        struct B1 {
            a: A,
            b: u64,
            c: bool,
        }

        impl Hashable for B1 {
            type D = ();

            fn to_roinput(&self) -> ROInput {
                self.a.to_roinput().append_u64(self.b).append_bool(self.c)
            }

            fn domain_string(_: Self::D) -> Option<String> {
                "B".to_string().into()
            }
        }

        #[derive(Clone, Debug)]
        struct B2 {
            a: A,
            b: u64,
            c: bool,
        }

        impl Hashable for B2 {
            type D = ();

            fn to_roinput(&self) -> ROInput {
                self.a
                    .to_roinput()
                    .append_roinput(ROInput::new().append_u64(self.b).append_bool(self.c))
            }

            fn domain_string(_: Self::D) -> Option<String> {
                "B".to_string().into()
            }
        }

        let a = A {
            x: 16830533,
            y: false,
            z: 39827791,
        };
        let b1 = B1 {
            a,
            b: 124819,
            c: true,
        };
        let b2 = B2 {
            a: b1.a.clone(),
            b: b1.b,
            c: b1.c,
        };

        assert_eq!(b1.to_roinput(), b2.to_roinput());

        let b2 = B2 {
            a: b1.a.clone(),
            b: b1.b,
            c: false,
        };
        assert_ne!(b1.to_roinput(), b2.to_roinput());

        let b2 = B2 {
            a: b1.a.clone(),
            b: b1.b + 1,
            c: b1.c,
        };
        assert_ne!(b1.to_roinput(), b2.to_roinput());
    }

    #[test]
    fn serialize_empty() {
        let roi = ROInput::new();

        let serialized = roi.serialize();

        assert_eq!(
            serialized,
            vec![0; SER_HEADER_SIZE],
            "Serialized empty ROInput should be zero bytes"
        );

        let deserialized_roi =
            ROInput::deserialize(&serialized).expect("Failed to deserialize ROInput");
        assert_eq!(
            roi, deserialized_roi,
            "Serialized and deserialized ROInput do not match"
        );
    }

    #[test]
    fn serialize_single_field() {
        let roi = ROInput::new().append_field(
            Fp::from_hex("41203c6bbac14b357301e1f386d80f52123fd00f02197491b690bddfa742ca22")
                .expect("failed to create field"),
        );

        let serialized = roi.serialize();
        let expected_length = SER_HEADER_SIZE + 32; // 32 bytes for the field
        assert_eq!(
            serialized.len(),
            expected_length,
            "Serialized ROInput length mismatch"
        );
        assert_eq!(
            serialized,
            [
                0x01, 0x00, 0x00, 0x00, // Field count
                0x00, 0x00, 0x00, 0x00, // Bit count
                0x41, 0x20, 0x3c, 0x6b, 0xba, 0xc1, 0x4b, 0x35, 0x73, 0x01, 0xe1, 0xf3, 0x86, 0xd8,
                0x0f, 0x52, 0x12, 0x3f, 0xd0, 0x0f, 0x02, 0x19, 0x74, 0x91, 0xb6, 0x90, 0xbd, 0xdf,
                0xa7, 0x42, 0xca, 0x22
            ]
            .to_vec(),
            "Serialized ROInput does not match expected output"
        );

        assert_eq!(
            roi,
            ROInput::deserialize(&serialized).expect("Failed to deserialize ROInput"),
            "Serialized and deserialized ROInput do not match"
        )
    }

    #[test]
    fn serialize_single_bool() {
        let roi = ROInput::new().append_bool(true);

        let serialized = roi.serialize();
        let expected_length = SER_HEADER_SIZE + 1; // 1 byte for the boolean
        assert_eq!(
            serialized.len(),
            expected_length,
            "Serialized ROInput length mismatch"
        );
        assert_eq!(
            serialized,
            [
                0x00, 0x00, 0x00, 0x00,
                0x01, 0x00, 0x00, 0x00,
                0x01  // Boolean value
            ]
            .to_vec(),
            "Serialized ROInput does not match expected output"
        );

        assert_eq!(
            roi,
            ROInput::deserialize(&serialized).expect("Failed to deserialize ROInput"),
            "Serialized and deserialized ROInput do not match"
        );
    }

    #[test]
    fn serialize_multiple_bools_length() {
        for i in 0..1024 {
            let roi = ROInput::new().append_bool(i % 2 == 0);
            let serialized = roi.serialize();

            // Deserialize and check if it matches
            let deserialized_roi =
                ROInput::deserialize(&serialized).expect("Failed to deserialize ROInput");
            assert_eq!(
                roi, deserialized_roi,
                "Serialized and deserialized ROInput do not match for i={}",
                i
            );
        }
    }

    #[test]
    fn deserialize_invalid() {
        let invalid_data = vec![0x01, 0x00, 0x00, 0x00]; // Invalid header, missing fields and bits

        let result = ROInput::deserialize(&invalid_data);
        assert!(
            result.is_err(),
            "Deserialization should fail for invalid data"
        );
    }

    #[test]
    fn deserialize_invalid_inconsistent_bitlen() {
        let invalid_data = vec![
            0x01, 0x00, 0x00, // Field count
            0x01, 0x00, 0x00, 0x00, // Bit count
            0x01, // Boolean value
                  // Missing bits for the boolean
        ];

        let result = ROInput::deserialize(&invalid_data);
        assert!(
            result.is_err(),
            "Deserialization should fail for inconsistent bit length"
        );
    }

    #[test]
    fn deserialize_invalid_message() {
        let msg = b"Test message for Mina compatibility".to_vec();
        let result = ROInput::deserialize(&msg);
        assert!(
            result.is_err(),
            "Deserialization should fail for invalid message format"
        );
    }

    #[test]
    fn deserialize_invalid_fieldheader() {
        let invalid_data = vec![
            0x01, 0x00, 0x00, 0x00, // Field count
            0x01, 0x00, 0x00, 0x00, // Bit count
            // Incorrect number of bytes for field header
            0x01, 0x02, 0x03, 0x04, 0x01, // Boolean value
        ];

        let result = ROInput::deserialize(&invalid_data);
        assert!(
            result.is_err(),
            "Deserialization should fail for overflow in field header"
        );
    }

    #[test]
    fn serialize_tx() {
        let tx_roi = ROInput::new()
            .append_field(
                Fp::from_hex("41203c6bbac14b357301e1f386d80f52123fd00f02197491b690bddfa742ca22")
                    .expect("failed to create field"),
            )
            .append_field(
                Fp::from_hex("992cdaf29ffe15b2bcea5d00e498ed4fffd117c197f0f98586e405f72ef88e00")
                    .expect("failed to create field"),
            ) // source
            .append_field(
                Fp::from_hex("3fba4fa71bce0dfdf709d827463036d6291458dfef772ff65e87bd6d1b1e062a")
                    .expect("failed to create field"),
            ) // receiver
            .append_u64(1000000) // fee
            .append_u64(1) // fee token
            .append_bool(true) // fee payer pk odd
            .append_u32(0) // nonce
            .append_u32(u32::MAX) // valid_until
            .append_bytes(&[0; 34]) // memo
            .append_bool(false) // tags[0]
            .append_bool(false) // tags[1]
            .append_bool(false) // tags[2]
            .append_bool(true) // sender pk odd
            .append_bool(false) // receiver pk odd
            .append_u64(1) // token_id
            .append_u64(10000000000) // amount
            .append_bool(false); // token_locked

        let tx_bytes = tx_roi.serialize();

        let deserialized_roi =
            ROInput::deserialize(&tx_bytes).expect("Failed to deserialize ROInput");

        assert_eq!(
            tx_roi, deserialized_roi,
            "Serialized and deserialized ROInput do not match"
        );
    }

    #[test]
    pub fn test_pack_to_field() {
        let roi = ROInput::new()
            .append_bool(true)
            .append_bool(false)
            .append_bool(true)
            .append_bool(true)
            .append_bool(false)
            .append_bool(false)
            .append_bool(true)
            .append_bool(false)
            .append_bool(true); // 9 bits

        let packed_fields = roi.to_packed_fields();
        assert_eq!(packed_fields.len(), 1);
        assert_eq!(packed_fields[0], Fp::from(0b101001101));
    }

    #[test]
    pub fn test_pack_to_field_more_than_255_bits() {
        let mut roi = ROInput::new();
        for i in 0..300 {
            roi = roi.append_bool(i % 2 == 0);
        }

        let packed_fields = roi.to_packed_fields();
        assert_eq!(packed_fields.len(), 2);
    }
}
