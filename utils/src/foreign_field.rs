//! Describes helpers for foreign field arithmetics
//! Generic parameters are as follows:
//! - `B` is a bit length of one limb
//! - `N` is a number of limbs that is used to represent one foreign field element

use crate::field_helpers::FieldHelpers;
use ark_ff::{Field, PrimeField};
use num_bigint::BigUint;
use std::{
    fmt::{Debug, Formatter},
    ops::{Index, IndexMut},
};

/// Represents a foreign field element
#[derive(Clone, PartialEq, Eq)]
/// Represents a foreign field element
pub struct ForeignElement<F: Field, const B: usize, const N: usize> {
    /// limbs in little endian order
    pub limbs: [F; N],
    /// number of limbs used for the foreign field element
    len: usize,
}

impl<F: Field, const B: usize, const N: usize> ForeignElement<F, B, N> {
    /// Creates a new foreign element from an array containing N limbs
    pub const fn new(limbs: [F; N]) -> Self {
        Self { limbs, len: N }
    }

    /// Creates a new foreign element representing the value zero
    #[must_use]
    pub fn zero() -> Self {
        Self {
            limbs: [F::zero(); N],
            len: N,
        }
    }

    /// Initializes a new foreign element from a [`BigUint`]
    ///
    /// # Panics
    ///
    /// Panics if the `BigUint` is too large to fit in the `N` limbs.
    #[must_use]
    pub fn from_biguint(big: &BigUint) -> Self {
        let vec = Self::big_to_vec(big);

        // create an array of N native elements containing the limbs
        // until the array is full in big endian, so most significant
        // limbs may be zero if the big number is smaller
        assert!(vec.len() <= N, "BigUint element is too large for N limbs");

        let mut limbs = [F::zero(); N];
        for (i, term) in vec.iter().enumerate() {
            limbs[i] = *term;
        }

        Self {
            limbs,
            len: limbs.len(),
        }
    }

    /// Initializes a new foreign element from an absolute `BigUint` but the equivalent
    /// foreign element obtained corresponds to the negated input. It first converts the
    /// input big element to a big integer modulo the foreign field modulus, and then
    /// computes the negation of the result.
    #[must_use]
    pub fn neg(&self, modulus: &BigUint) -> Self {
        let big = self.to_biguint();
        let ok = big % modulus;
        let neg = modulus - ok;
        Self::from_biguint(&neg)
    }

    /// Initializes a new foreign element from a set of bytes in big endian
    #[must_use]
    pub fn from_be(bytes: &[u8]) -> Self {
        Self::from_biguint(&BigUint::from_bytes_be(bytes))
    }

    /// Obtains the big integer representation of the foreign field element
    #[must_use]
    pub fn to_biguint(&self) -> BigUint {
        let mut bytes = vec![];
        if B.is_multiple_of(8) {
            // limbs are stored in little endian
            for limb in self.limbs {
                let crumb = &limb.to_bytes()[0..B / 8];
                bytes.extend_from_slice(crumb);
            }
        } else {
            let mut bits: Vec<bool> = vec![];
            for limb in self.limbs {
                // Only take lower B bits, as there might be more (zeroes) in the high ones.
                bits.extend(limb.to_bits().into_iter().take(B));
            }

            let bytes_len = (B * N).div_ceil(8);
            bytes = vec![0u8; bytes_len];
            for (i, &bit) in bits.iter().enumerate() {
                bytes[i / 8] |= u8::from(bit) << (i % 8);
            }
        }
        BigUint::from_bytes_le(&bytes)
    }

    /// Split a foreign field element into a vector of `B` (limb bitsize) bits field
    /// elements of type `F` in little-endian. Right now it is written
    /// so that it gives `N` (limb count) limbs, even if it fits in less bits.
    fn big_to_vec(fe: &BigUint) -> Vec<F> {
        if B.is_multiple_of(8) {
            let bytes = fe.to_bytes_le();
            bytes
                .chunks(B / 8)
                .map(|chunk| F::from_random_bytes(chunk).expect("failed to deserialize"))
                .collect()
        } else {
            // Quite inefficient
            let mut bits = vec![]; // can be slice not vec, but B*N is not const?
            assert!(
                fe.bits() <= (B * N) as u64,
                "BigUint too big to be represented in B*N elements"
            );
            for i in 0..B * N {
                bits.push(fe.bit(i as u64));
            }
            bits.chunks(B)
                .map(|chunk| F::from_bits(chunk).expect("failed to deserialize"))
                .collect()
        }
    }
}

impl<F: PrimeField, const B: usize, const N: usize> ForeignElement<F, B, N> {
    /// Initializes a new foreign element from an element in the native field
    pub fn from_field(field: F) -> Self {
        Self::from_biguint(&field.into())
    }
}

impl<F: Field, const B: usize, const N: usize> Index<usize> for ForeignElement<F, B, N> {
    type Output = F;
    fn index(&self, idx: usize) -> &Self::Output {
        &self.limbs[idx]
    }
}

impl<F: Field, const B: usize, const N: usize> IndexMut<usize> for ForeignElement<F, B, N> {
    fn index_mut(&mut self, idx: usize) -> &mut Self::Output {
        &mut self.limbs[idx]
    }
}

impl<F: Field, const B: usize, const N: usize> Debug for ForeignElement<F, B, N> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "ForeignElement(")?;
        for i in 0..self.len {
            write!(f, "{:?}", self.limbs[i].to_hex())?;
            if i != self.len - 1 {
                write!(f, ", ")?;
            }
        }
        write!(f, ")")
    }
}

/// Foreign field helpers for `B` the limb size.
pub trait ForeignFieldHelpers<F, const B: usize> {
    /// 2^{B}
    fn two_to_limb() -> F;

    /// 2^{2 * B}
    fn two_to_2limb() -> F;

    /// 2^{3 * B}
    fn two_to_3limb() -> F;
}

impl<F: Field, const B: usize, const N: usize> ForeignFieldHelpers<F, B>
    for ForeignElement<F, B, N>
{
    fn two_to_limb() -> F {
        F::from(2u64).pow([B as u64])
    }

    fn two_to_2limb() -> F {
        F::from(2u64).pow([2 * B as u64])
    }

    fn two_to_3limb() -> F {
        // Self?
        F::from(2u64).pow([3 * B as u64])
    }
}
