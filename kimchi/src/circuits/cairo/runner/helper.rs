use ark_ff::{FftField, PrimeField};
//use ark_serialize::CanonicalSerialize;
use bitvec::{prelude::*, view::AsBits};
use o1_utils::FieldHelpers;

/// Field element helpers (TODO move to utils inside FieldHelpers)
pub trait FieldBit<F: PrimeField> {
    /// Serialize to bits
    fn to_bits(self) -> Vec<u8>;

    /// Returns field element as byte, if it fits
    fn to_byte(self) -> u8;

    /// Return pos-th 16-bit chunk as another field element
    fn chunk(self, pos: usize) -> F;
}

impl<F: PrimeField> FieldBit<F> for F {
    fn to_bits(self) -> Vec<u8> {
        // We are representing bits with u8 as we don't have u2
        let bytes = self.to_bytes();
        let mut bits = Vec::new();
        for b in bytes {
            let mut b1 = b;
            for _ in 0..8 {
                bits.push(b1 % 2);
                b1 = b1 >> 1;
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
}

#[cfg(test)]
mod tests {
    use ark_ec::AffineCurve;
    use mina_curves::pasta::pallas;

    /// Affine curve point type
    pub use pallas::Affine as CurvePoint;
    /// Base field element type
    pub type BaseField = <CurvePoint as AffineCurve>::BaseField;

    use super::*;

    #[test]
    fn test_field_to_bits() {
        let fe = BaseField::from(256u32);
        let bits = fe.to_bits();
        //println!("{:?}", &bits[0..16]);
    }

    #[test]
    fn test_field_to_chunks() {
        let fe = BaseField::from(0x480680017fff8000u64);
        let chunk = fe.chunk(1);
        assert_eq!(chunk, BaseField::from(0x7fff));
    }
}
