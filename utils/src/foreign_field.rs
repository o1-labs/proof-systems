//! Describes helpers for foreign field arithmetics

use std::fmt::Display;

use crate::{field_helpers::FieldHelpers, serialization::SerdeAs};
use ark_ff::{FftField, Field, PrimeField};
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

/// Limb length for foreign field elements
pub const LIMB_BITS: usize = 88;

/// Number of desired limbs for foreign field elements
pub const LIMB_COUNT: usize = 3;

/// The foreign field modulus of secp256k1 is the prime number (in big endian)
/// FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE FFFFFC2F
/// given by the computation 2^256 - 2^32 - 2^9 - 2^8 - 2^7 - 2^6 - 2^4 - 1
/// more information here  <https://en.bitcoin.it/wiki/Secp256k1>
pub const SECP256K1_MOD: &[u8] = &[
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFC, 0x2F,
];

/// Bit length of the foreign field modulus
pub const FOREIGN_BITS: usize = 8 * SECP256K1_MOD.len(); // 256 bits

#[serde_as]
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
/// Represents a foreign field element
pub struct ForeignElement<F: Field, const N: usize> {
    /// limbs in little endian order
    #[serde_as(as = "[SerdeAs; N]")]
    pub limbs: [F; N],
    /// number of limbs used for the foreign field element
    pub len: usize,
}

impl<F: Field, const N: usize> ForeignElement<F, N> {
    /// Initializes a new foreign element from a big unsigned integer
    /// Panics if the BigUint is too large to fit in the `N` limbs
    pub fn from_biguint(big: BigUint) -> Self {
        let vec = ForeignElement::<F, N>::big_to_vec(big);

        // create an array of N native elements containing the limbs
        // until the array is full in big endian, so most significant
        // limbs may be zero if the big number is smaller
        if vec.len() > N {
            panic!("BigUint element is too large for N limbs");
        }

        let mut limbs = [F::zero(); N];
        for (i, term) in vec.iter().enumerate() {
            limbs[i] = *term;
        }

        Self {
            limbs,
            len: limbs.len(),
        }
    }

    /// Initializes a new foreign element from a set of bytes in big endian
    pub fn from_be(bytes: &[u8]) -> Self {
        Self::from_biguint(BigUint::from_bytes_be(bytes))
    }

    /// Obtains the big integer representation of the foreign field element
    pub fn to_biguint(&self) -> BigUint {
        let mut bytes = vec![];
        // limbs are stored in little endian
        for limb in self.limbs {
            let crumb = &limb.to_bytes()[0..LIMB_BITS / 8];
            bytes.extend_from_slice(crumb);
        }
        BigUint::from_bytes_le(&bytes)
    }

    /// Split a foreign field element into a vector of `LIMB_BITS` bits field elements of type `F` in little-endian.
    /// Right now it is written so that it gives `LIMB_COUNT` limbs, even if it fits in less bits.
    fn big_to_vec(fe: BigUint) -> Vec<F> {
        let bytes = fe.to_bytes_le();
        let chunks: Vec<&[u8]> = bytes.chunks(LIMB_BITS / 8).collect();
        chunks
            .iter()
            .map(|chunk| F::from_random_bytes(chunk).expect("failed to deserialize"))
            .collect()
    }
}

impl<F: PrimeField, const N: usize> ForeignElement<F, N> {
    /// Initializes a new foreign element from an element in the native field
    pub fn from_field(field: F) -> Self {
        Self::from_biguint(field.into())
    }
}

impl<F: FftField> ForeignElement<F, 3> {
    /// Creates a new foreign element from an array containing 3 limbs
    pub fn create(limbs: [F; 3]) -> Self {
        Self { limbs, len: 3 }
    }

    /// Returns a reference to the lowest limb of the foreign element
    pub fn lo(&self) -> &F {
        &self.limbs[0]
    }

    /// Returns a reference to the middle limb of the foreign element
    pub fn mi(&self) -> &F {
        &self.limbs[1]
    }

    /// Returns a reference to the highest limb of the foreign element
    pub fn hi(&self) -> &F {
        &self.limbs[2]
    }
}

impl<F: FftField, const N: usize> Display for ForeignElement<F, N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut s = String::new();
        let order = ["lo", "mi", "hi"];
        s += "{ ";
        for (i, limb) in self.limbs.iter().enumerate() {
            let hex = limb.to_hex();
            let len = LIMB_BITS / 8 * 2;
            s += &(order[i % N].to_owned() + ": ");
            s.push_str(&hex[0..len as usize]);
            if i < N - 1 {
                s += " , ";
            }
        }
        s += " }";
        write!(f, "{}", s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field_helpers::FieldHelpers;
    use ark_ec::AffineCurve;
    use ark_ff::One;
    use mina_curves::pasta::pallas;

    /// Affine curve point type
    pub use pallas::Pallas as CurvePoint;
    /// Base field element type
    pub type BaseField = <CurvePoint as AffineCurve>::BaseField;
    #[test]
    fn test_big_be() {
        let bytes = SECP256K1_MOD;
        let big = BigUint::from_bytes_be(bytes);
        assert_eq!(
            ForeignElement::<BaseField, 3>::from_be(bytes),
            ForeignElement::<BaseField, 3>::from_biguint(big)
        );
    }

    #[test]
    fn test_to_biguint() {
        let bytes = SECP256K1_MOD;
        let big = BigUint::from_bytes_be(bytes);
        let fe = ForeignElement::<BaseField, 3>::from_be(bytes);
        assert_eq!(fe.to_biguint(), big);
    }

    #[test]
    fn test_from_biguint() {
        let one = ForeignElement::<BaseField, 3>::from_be(&[0x01]);
        assert_eq!(
            BaseField::from_biguint(one.to_biguint()).unwrap(),
            BaseField::one()
        );

        let max_big = BaseField::modulus_biguint() - 1u32;
        let max_fe = ForeignElement::<BaseField, 3>::from_biguint(max_big.clone());
        assert_eq!(
            BaseField::from_biguint(max_fe.to_biguint()).unwrap(),
            BaseField::from_bytes(&max_big.to_bytes_le()).unwrap(),
        );
    }
}
