/**
 * MinimalField trait implementation `Fp` which only depends on an `FpBackend` trait
 *
 * Most of this code was copied over from ark_ff::Fp
 */
use crate::pasta::wasm_friendly::bigint32::BigInt;
use ark_ff::{One, Zero};
use ark_serialize::{
    CanonicalDeserialize, CanonicalSerialize, Compress, Read, SerializationError, Valid, Validate,
    Write,
};
use derivative::Derivative;
use num_bigint::BigUint;
use std::{
    marker::PhantomData,
    ops::{Add, AddAssign, Mul, MulAssign},
};

use super::minimal_field::MinimalField;

pub trait FpBackend<const N: usize>: Send + Sync + 'static + Sized {
    const MODULUS: BigInt<N>;
    const ZERO: BigInt<N>;
    const ONE: BigInt<N>;

    fn add_assign(a: &mut Fp<Self, N>, b: &Fp<Self, N>);
    fn mul_assign(a: &mut Fp<Self, N>, b: &Fp<Self, N>);

    /// Construct a field element from an integer in the range
    /// `0..(Self::MODULUS - 1)`. Returns `None` if the integer is outside
    /// this range.
    fn from_bigint(x: BigInt<N>) -> Option<Fp<Self, N>>;
    fn to_bigint(x: Fp<Self, N>) -> BigInt<N>;

    fn pack(x: Fp<Self, N>) -> Vec<u64>;
}

/// Represents an element of the prime field F_p, where `p == P::MODULUS`.
/// This type can represent elements in any field of size at most N * 64 bits.
#[derive(Derivative)]
#[derivative(
    Default(bound = ""),
    Hash(bound = ""),
    Copy(bound = ""),
    PartialEq(bound = ""),
    Eq(bound = ""),
    Debug(bound = "")
)]
pub struct Fp<P: FpBackend<N>, const N: usize>(
    pub BigInt<N>,
    #[derivative(Debug = "ignore")]
    #[doc(hidden)]
    pub PhantomData<P>,
);

impl<P: FpBackend<N>, const N: usize> Clone for Fp<P, N> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<P: FpBackend<N>, const N: usize> Fp<P, N> {
    pub fn new(bigint: BigInt<N>) -> Self {
        Fp(bigint, Default::default())
    }

    #[inline]
    pub fn from_bigint(r: BigInt<N>) -> Option<Self> {
        P::from_bigint(r)
    }
    #[inline]
    pub fn into_bigint(self) -> BigInt<N> {
        P::to_bigint(self)
    }

    pub fn to_bytes_le(self) -> Vec<u8> {
        let chunks = P::pack(self).into_iter().map(|x| x.to_le_bytes());
        let mut bytes = Vec::with_capacity(chunks.len() * 8);
        for chunk in chunks {
            bytes.extend_from_slice(&chunk);
        }
        bytes
    }
}

// coerce into Fp from either BigInt<N> or [u32; N]

impl<P: FpBackend<N>, const N: usize> From<BigInt<N>> for Fp<P, N> {
    fn from(val: BigInt<N>) -> Self {
        Fp::from_bigint(val).unwrap()
    }
}

impl<P: FpBackend<N>, const N: usize> From<[u32; N]> for Fp<P, N> {
    fn from(val: [u32; N]) -> Self {
        Fp::from_bigint(BigInt(val)).unwrap()
    }
}

// field

impl<P: FpBackend<N>, const N: usize> MinimalField for Fp<P, N> {
    fn square_in_place(&mut self) -> &mut Self {
        // implemented with mul_assign for now
        let self_copy = *self;
        self.mul_assign(&self_copy);
        self
    }
}

// add, zero

impl<P: FpBackend<N>, const N: usize> Zero for Fp<P, N> {
    #[inline]
    fn zero() -> Self {
        Fp::new(P::ZERO)
    }

    #[inline]
    fn is_zero(&self) -> bool {
        *self == Self::zero()
    }
}

impl<'a, P: FpBackend<N>, const N: usize> AddAssign<&'a Self> for Fp<P, N> {
    #[inline]
    fn add_assign(&mut self, other: &Self) {
        P::add_assign(self, other)
    }
}
impl<P: FpBackend<N>, const N: usize> Add<Self> for Fp<P, N> {
    type Output = Self;

    #[inline]
    fn add(mut self, other: Self) -> Self {
        self.add_assign(&other);
        self
    }
}
impl<'a, P: FpBackend<N>, const N: usize> Add<&'a Fp<P, N>> for Fp<P, N> {
    type Output = Self;

    #[inline]
    fn add(mut self, other: &Self) -> Self {
        self.add_assign(other);
        self
    }
}

// mul, one

impl<P: FpBackend<N>, const N: usize> One for Fp<P, N> {
    #[inline]
    fn one() -> Self {
        Fp::new(P::ONE)
    }

    #[inline]
    fn is_one(&self) -> bool {
        *self == Self::one()
    }
}
impl<'a, P: FpBackend<N>, const N: usize> MulAssign<&'a Self> for Fp<P, N> {
    #[inline]
    fn mul_assign(&mut self, other: &Self) {
        P::mul_assign(self, other)
    }
}
impl<P: FpBackend<N>, const N: usize> Mul<Self> for Fp<P, N> {
    type Output = Self;

    #[inline]
    fn mul(mut self, other: Self) -> Self {
        self.mul_assign(&other);
        self
    }
}
impl<'a, P: FpBackend<N>, const N: usize> Mul<&'a Fp<P, N>> for Fp<P, N> {
    type Output = Self;

    #[inline]
    fn mul(mut self, other: &Self) -> Self {
        self.mul_assign(other);
        self
    }
}

// (de)serialization

impl<P: FpBackend<N>, const N: usize> CanonicalSerialize for Fp<P, N> {
    #[inline]
    fn serialize_with_mode<W: Write>(
        &self,
        writer: W,
        compress: Compress,
    ) -> Result<(), SerializationError> {
        self.0.serialize_with_mode(writer, compress)
    }

    #[inline]
    fn serialized_size(&self, compress: Compress) -> usize {
        self.0.serialized_size(compress)
    }
}

impl<P: FpBackend<N>, const N: usize> Valid for Fp<P, N> {
    fn check(&self) -> Result<(), SerializationError> {
        Ok(())
    }
}

impl<P: FpBackend<N>, const N: usize> CanonicalDeserialize for Fp<P, N> {
    fn deserialize_with_mode<R: Read>(
        reader: R,
        compress: Compress,
        validate: Validate,
    ) -> Result<Self, SerializationError> {
        Self::from_bigint(BigInt::deserialize_with_mode(reader, compress, validate)?)
            .ok_or(SerializationError::InvalidData)
    }
}

// display

impl<P: FpBackend<N>, const N: usize> From<Fp<P, N>> for BigUint {
    #[inline]
    fn from(val: Fp<P, N>) -> BigUint {
        BigUint::from_bytes_le(&val.to_bytes_le())
    }
}

impl<P: FpBackend<N>, const N: usize> std::fmt::Display for Fp<P, N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        BigUint::from(*self).fmt(f)
    }
}
