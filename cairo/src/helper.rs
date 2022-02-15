//! This module inlcudes some field helpers that are useful for Cairo

use ark_ff::PrimeField;
use o1_utils::FieldHelpers;

//(TODO move to utils inside FieldHelpers)

/// Field element helpers for Cairo
pub trait CairoFieldHelpers<F: PrimeField> {
    /// Serialize to bits
    fn to_bits(self) -> Vec<u8>;

    /// Return field element as byte, if it fits
    fn to_byte(self) -> u8;

    /// Return pos-th 16-bit chunk as another field element
    fn chunk(self, pos: usize) -> F;

    /// Return first 64 bits of the field element
    fn to_u64(self) -> u64;

    /// Return a field element in hexadecimal in little endian
    fn to_hex_le(self) -> String;

    /// Return a vector of field elements from a vector of i128
    fn vec_to_field(vec: Vec<i128>) -> Vec<F>;
}

impl<F: PrimeField> CairoFieldHelpers<F> for F {
    fn to_bits(self) -> Vec<u8> {
        // We are representing bits with u8 as we don't have u2
        let bytes = self.to_bytes();
        let mut bits = Vec::new();
        for b in bytes {
            let mut b1 = b;
            for _ in 0..8 {
                bits.push(b1 % 2);
                b1 >>= 1;
            }
        }
        bits
    }

    fn to_byte(self) -> u8 {
        self.to_bytes()[0]
    }

    fn chunk(self, pos: usize) -> F {
        let bytes = self.to_bytes();
        let chunk = u16::from(bytes[2 * pos]) + u16::from(bytes[2 * pos + 1]) * 2u16.pow(8);
        F::from(chunk)
    }

    fn to_u64(self) -> u64 {
        let bytes = self.to_bytes();
        let mut acc: u64 = 0;
        for i in 0..8 {
            acc += 2u64.pow(i * 8) * (bytes[i as usize] as u64);
        }
        acc
    }

    fn to_hex_le(self) -> String {
        let mut bytes = self.to_bytes();
        bytes.reverse();
        hex::encode(bytes)
    }

    fn vec_to_field(vec: Vec<i128>) -> Vec<F> {
        vec.iter()
            .map(|i| {
                if *i < 0 {
                    -F::from((-(*i)) as u64)
                } else {
                    F::from((*i) as u64)
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ec::AffineCurve;
    use mina_curves::pasta::pallas;
    use o1_utils::FieldHelpers;

    /// Affine curve point type
    pub use pallas::Affine as CurvePoint;
    /// Base field element type
    pub type BaseField = <CurvePoint as AffineCurve>::BaseField;

    #[test]
    fn test_field_to_bits() {
        let fe = BaseField::from(256u32);
        let bits = fe.to_bits();
        println!("{:?}", &bits[0..16]);
    }

    #[test]
    fn test_field_to_chunks() {
        let fe = BaseField::from(0x480680017fff8000u64);
        let chunk = fe.chunk(1);
        assert_eq!(chunk, BaseField::from(0x7fff));
    }

    #[test]
    fn test_hex_and_u64() {
        let fe = BaseField::from(0x480680017fff8000u64);
        let change = BaseField::from_hex(&fe.to_hex()).unwrap();
        assert_eq!(fe, change);
        let word = change.to_u64();
        assert_eq!(word, 0x480680017fff8000u64);
    }
}
