/**
 * MinimalField trait implementation `Fp` which only depends on an `FpBackend` trait
 *
 * Most of this code was copied over from ark_ff::Fp
 */
use crate::pasta::wasm_friendly::bigint32_attempt2::BigInt;
use ark_ff::{AdditiveGroup, FftField, Field, One, PrimeField, Zero};
use ark_serialize::{
    CanonicalDeserialize, CanonicalDeserializeWithFlags, CanonicalSerialize,
    CanonicalSerializeWithFlags, Compress, Flags, Read, SerializationError, Valid, Validate, Write,
};
use derivative::Derivative;
use num_bigint::BigUint;
use std::{
    cmp::Ordering,
    iter::{Iterator, Product, Sum},
    marker::PhantomData,
    ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Sub, SubAssign},
    str::FromStr,
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

impl<P: FpBackend<N>, const N: usize> zeroize::DefaultIsZeroes for Fp<P, N> {}

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

impl<P: FpBackend<N>, const N: usize> Into<BigInt<N>> for Fp<P, N> {
    fn into(self) -> BigInt<N> {
        Fp::into_bigint(self)
    }
}

impl<P: FpBackend<N>, const N: usize> From<[u32; N]> for Fp<P, N> {
    fn from(val: [u32; N]) -> Self {
        Fp::from_bigint(BigInt::from_digits(val)).unwrap()
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

// add, zero, neg

impl<P: FpBackend<N>, const N: usize> Neg for Fp<P, N> {
    type Output = Self;

    #[must_use]
    fn neg(self) -> Self {
        if !self.is_zero() {
            let mut tmp = P::MODULUS;
            tmp.sub_noborrow(&self.0);
            Fp(tmp, PhantomData)
        } else {
            self
        }
    }
}

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

impl<'a, P: FpBackend<N>, const N: usize> AddAssign<&'a mut Self> for Fp<P, N> {
    #[inline]
    fn add_assign(&mut self, other: &mut Self) {
        P::add_assign(self, other)
    }
}

impl<P: FpBackend<N>, const N: usize> AddAssign<Self> for Fp<P, N> {
    #[inline]
    fn add_assign(&mut self, other: Self) {
        P::add_assign(self, &other)
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

impl<'a, P: FpBackend<N>, const N: usize> Add<&'a mut Fp<P, N>> for Fp<P, N> {
    type Output = Self;

    #[inline]
    fn add(mut self, other: &mut Self) -> Self {
        self.add_assign(other);
        self
    }
}

////////////////////////////////////////////////////////////////////////////
// Mul, one
////////////////////////////////////////////////////////////////////////////

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

impl<'a, P: FpBackend<N>, const N: usize> MulAssign<&'a mut Self> for Fp<P, N> {
    #[inline]
    fn mul_assign(&mut self, other: &mut Self) {
        P::mul_assign(self, other)
    }
}

impl<P: FpBackend<N>, const N: usize> MulAssign<Self> for Fp<P, N> {
    #[inline]
    fn mul_assign(&mut self, other: Self) {
        P::mul_assign(self, &other)
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

impl<'a, P: FpBackend<N>, const N: usize> Mul<&'a mut Fp<P, N>> for Fp<P, N> {
    type Output = Self;

    #[inline]
    fn mul(mut self, other: &mut Self) -> Self {
        self.mul_assign(other);
        self
    }
}

////////////////////////////////////////////////////////////////////////////
// (De)Serialization
////////////////////////////////////////////////////////////////////////////

impl<P: FpBackend<N>, const N: usize> CanonicalSerializeWithFlags for Fp<P, N> {
    fn serialize_with_flags<W: ark_std::io::Write, F: Flags>(
        &self,
        mut writer: W,
        flags: F,
    ) -> Result<(), SerializationError> {
        todo!()
        //if F::BIT_SIZE > 8 {
        //    return Err(SerializationError::NotEnoughSpace);
        //}
        //let output_byte_size = buffer_byte_size(C::MODULUS_BITS as usize + F::BIT_SIZE);
        //let mut bytes = [0u8; 4 * 8 + 1];
        //self.write(&mut bytes[..4 * 8])?;
        //bytes[output_byte_size - 1] |= flags.u8_bitmask();
        //writer.write_all(&bytes[..output_byte_size])?;
        //Ok(())
    }
    fn serialized_size_with_flags<F: Flags>(&self) -> usize {
        todo!()
        // buffer_byte_size(P::MODULUS_BITS as usize + F::BIT_SIZE)
    }
}

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

impl<P: FpBackend<N>, const N: usize> CanonicalDeserializeWithFlags for Fp<P, N> {
    fn deserialize_with_flags<R: ark_std::io::Read, F: Flags>(
        mut reader: R,
    ) -> Result<(Self, F), SerializationError> {
        todo!()
        //if F::BIT_SIZE > 8 {
        //    return Err(SerializationError::NotEnoughSpace);
        //}
        //let output_byte_size = buffer_byte_size(C::MODULUS_BITS as usize + F::BIT_SIZE);
        //let mut masked_bytes = [0; 4 * 8 + 1];
        //reader.read_exact(&mut masked_bytes[..output_byte_size])?;
        //let flags = F::from_u8_remove_flags(&mut masked_bytes[output_byte_size - 1])
        //    .ok_or(SerializationError::UnexpectedFlags)?;
        //Ok((Self::read(&masked_bytes[..])?, flags))
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

////////////////////////////////////////////////////////////////////////////
// div
////////////////////////////////////////////////////////////////////////////

impl<'a, P: FpBackend<N>, const N: usize> DivAssign<&'a Self> for Fp<P, N> {
    fn div_assign(&mut self, other: &'a Self) {
        self.mul_assign(&other.inverse().unwrap());
    }
}

impl<'a, P: FpBackend<N>, const N: usize> DivAssign<&'a mut Self> for Fp<P, N> {
    fn div_assign(&mut self, other: &'a mut Self) {
        self.mul_assign(&other.inverse().unwrap());
    }
}

impl<P: FpBackend<N>, const N: usize> DivAssign<Self> for Fp<P, N> {
    fn div_assign(&mut self, other: Self) {
        self.div_assign(&other)
    }
}

impl<P: FpBackend<N>, const N: usize> Div<Self> for Fp<P, N> {
    type Output = Self;
    fn div(mut self, other: Self) -> Self {
        self.div_assign(other);
        self
    }
}

impl<'a, P: FpBackend<N>, const N: usize> Div<&'a Self> for Fp<P, N> {
    type Output = Self;
    fn div(mut self, other: &'a Self) -> Self {
        self.div_assign(other);
        self
    }
}

impl<'a, P: FpBackend<N>, const N: usize> Div<&'a mut Self> for Fp<P, N> {
    type Output = Self;
    fn div(mut self, other: &'a mut Self) -> Self {
        self.div_assign(other);
        self
    }
}

////////////////////////////////////////////////////////////////////////////
// sub
////////////////////////////////////////////////////////////////////////////

impl<P: FpBackend<N>, const N: usize> SubAssign<Self> for Fp<P, N> {
    fn sub_assign(&mut self, other: Self) {
        if other.0 > self.0 {
            self.0.add_nocarry(&P::MODULUS);
        }
        self.0.sub_noborrow(&other.0);
    }
}

impl<'a, P: FpBackend<N>, const N: usize> SubAssign<&'a Self> for Fp<P, N> {
    fn sub_assign(&mut self, other: &'a Self) {
        if other.0 > self.0 {
            self.0.add_nocarry(&P::MODULUS);
        }
        self.0.sub_noborrow(&other.0);
    }
}

impl<'a, P: FpBackend<N>, const N: usize> SubAssign<&'a mut Self> for Fp<P, N> {
    fn sub_assign(&mut self, other: &'a mut Self) {
        if other.0 > self.0 {
            self.0.add_nocarry(&P::MODULUS);
        }
        self.0.sub_noborrow(&other.0);
    }
}

impl<P: FpBackend<N>, const N: usize> Sub<Self> for Fp<P, N> {
    type Output = Self;
    fn sub(mut self, other: Self) -> Self {
        self.sub_assign(other);
        self
    }
}

impl<'a, P: FpBackend<N>, const N: usize> Sub<&'a Self> for Fp<P, N> {
    type Output = Self;
    fn sub(mut self, other: &'a Self) -> Self {
        self.sub_assign(other);
        self
    }
}

impl<'a, P: FpBackend<N>, const N: usize> Sub<&'a mut Self> for Fp<P, N> {
    type Output = Self;
    fn sub(mut self, other: &'a mut Self) -> Self {
        self.sub_assign(other);
        self
    }
}

// display

impl<P: FpBackend<N>, const N: usize> From<BigUint> for Fp<P, N> {
    #[inline]
    fn from(val: BigUint) -> Fp<P, N> {
        Self::from_le_bytes_mod_order(&val.to_bytes_le())
        //BigUint::from_bytes_le(&val.to_bytes_le())
    }
}

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

impl<P: FpBackend<N>, const N: usize> FromStr for Fp<P, N> {
    type Err = ();
    /// Interpret a string of numbers as a (congruent) prime field element.
    /// Does not accept unnecessary leading zeroes or a blank string.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        todo!()
        //if s.is_empty() {
        //    return Err(());
        //}
        //if s == "0" {
        //    return Ok(Self::zero());
        //}
        //let mut res = Self::zero();
        //let ten = Self::try_from(BigInt::from(10u32)).unwrap();
        //let mut first_digit = true;
        //for c in s.chars() {
        //    match c.to_digit(10) {
        //        Some(c) => {
        //            if first_digit {
        //                if c == 0 {
        //                    return Err(());
        //                }
        //                first_digit = false;
        //            }
        //            res.mul_assign(&ten);
        //            let digit = Self::from(u64::from(c));
        //            res.add_assign(&digit);
        //        }
        //        None => {
        //            return Err(());
        //        }
        //    }
        //}
        //if !res.is_valid() {
        //    Err(())
        //} else {
        //    Ok(res)
        //}
    }
}

////////////////////////////////////////////////////////////////////////////
// distribution
////////////////////////////////////////////////////////////////////////////

impl<P: FpBackend<N>, const N: usize> ark_std::rand::distributions::Distribution<Fp<P, N>>
    for ark_std::rand::distributions::Standard
{
    #[inline]
    fn sample<R: ark_std::rand::Rng + ?Sized>(&self, rng: &mut R) -> Fp<P, N> {
        todo!()
        //loop {
        //    if !(C::REPR_SHAVE_BITS <= 64) {
        //        panic!("assertion failed: P::REPR_SHAVE_BITS <= 64")
        //    }
        //    let mask = if C::REPR_SHAVE_BITS == 64 {
        //        0
        //    } else {
        //        core::u64::MAX >> C::REPR_SHAVE_BITS
        //    };
        //    let mut tmp: [u64; 4] = rng.sample(ark_std::rand::distributions::Standard);
        //    tmp.as_mut().last_mut().map(|val| *val &= mask);
        //    let is_fp = match C::T.0[0] {
        //        0x192d30ed => true,
        //        0xc46eb21 => false,
        //        _ => panic!(),
        //    };
        //    const FP_MODULUS: [u64; 4] = [
        //        0x992d30ed00000001,
        //        0x224698fc094cf91b,
        //        0x0,
        //        0x4000000000000000,
        //    ];
        //    const FQ_MODULUS: [u64; 4] = [
        //        0x8c46eb2100000001,
        //        0x224698fc0994a8dd,
        //        0x0,
        //        0x4000000000000000,
        //    ];
        //    let (modulus, inv) = if is_fp {
        //        (FP_MODULUS, 11037532056220336127)
        //    } else {
        //        (FQ_MODULUS, 10108024940646105087)
        //    };
        //    let is_valid = || {
        //        for (random, modulus) in tmp.iter().copied().zip(modulus).rev() {
        //            if random > modulus {
        //                return false;
        //            } else if random < modulus {
        //                return true;
        //            }
        //        }
        //        false
        //    };
        //    if !is_valid() {
        //        continue;
        //    }
        //    let mut r = tmp;
        //    // Montgomery Reduction
        //    for i in 0..4 {
        //        let k = r[i].wrapping_mul(inv);
        //        let mut carry = 0;
        //        mac_with_carry!(r[i], k, modulus[0] as _, &mut carry);
        //        for j in 1..4 {
        //            r[(j + i) % 4] = mac_with_carry!(r[(j + i) % 4], k, modulus[j], &mut carry);
        //        }
        //        r[i % 4] = carry;
        //    }
        //    tmp = r;
        //    return Fp256::<C>::from_repr(BigInteger256::from_64x4(tmp)).unwrap();
        //}
    }
}

////////////////////////////////////////////////////////////////////////////
// Misc
////////////////////////////////////////////////////////////////////////////

impl<P: FpBackend<N>, const N: usize> Sum<Self> for Fp<P, N> {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::zero(), core::ops::Add::add)
    }
}

impl<P: FpBackend<N>, const N: usize> Product<Self> for Fp<P, N> {
    fn product<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::one(), Mul::mul)
    }
}

impl<'a, P: FpBackend<N>, const N: usize> Sum<&'a Self> for Fp<P, N> {
    fn sum<I: Iterator<Item = &'a Self>>(iter: I) -> Self {
        iter.fold(Self::zero(), core::ops::Add::add)
    }
}

impl<'a, P: FpBackend<N>, const N: usize> Product<&'a Self> for Fp<P, N> {
    fn product<I: Iterator<Item = &'a Self>>(iter: I) -> Self {
        iter.fold(Self::one(), Mul::mul)
    }
}

impl<P: FpBackend<N>, const N: usize> Ord for Fp<P, N> {
    #[inline(always)]
    fn cmp(&self, other: &Self) -> Ordering {
        self.into_bigint().cmp(&other.into_bigint())
    }
}

impl<P: FpBackend<N>, const N: usize> PartialOrd for Fp<P, N> {
    #[inline(always)]
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<P: FpBackend<N>, const N: usize> From<u128> for Fp<P, N> {
    fn from(other: u128) -> Self {
        todo!()
    }
}

impl<P: FpBackend<N>, const N: usize> From<u64> for Fp<P, N> {
    fn from(other: u64) -> Self {
        todo!()
    }
}

impl<P: FpBackend<N>, const N: usize> From<u32> for Fp<P, N> {
    fn from(other: u32) -> Self {
        todo!()
    }
}

impl<P: FpBackend<N>, const N: usize> From<u16> for Fp<P, N> {
    fn from(other: u16) -> Self {
        todo!()
    }
}

impl<P: FpBackend<N>, const N: usize> From<u8> for Fp<P, N> {
    fn from(other: u8) -> Self {
        todo!()
    }
}

impl<P: FpBackend<N>, const N: usize> From<i128> for Fp<P, N> {
    fn from(other: i128) -> Self {
        todo!()
    }
}

impl<P: FpBackend<N>, const N: usize> From<i64> for Fp<P, N> {
    fn from(other: i64) -> Self {
        todo!()
    }
}

impl<P: FpBackend<N>, const N: usize> From<i32> for Fp<P, N> {
    fn from(other: i32) -> Self {
        todo!()
    }
}

impl<P: FpBackend<N>, const N: usize> From<i16> for Fp<P, N> {
    fn from(other: i16) -> Self {
        todo!()
    }
}

impl<P: FpBackend<N>, const N: usize> From<i8> for Fp<P, N> {
    fn from(other: i8) -> Self {
        todo!()
    }
}

impl<P: FpBackend<N>, const N: usize> From<bool> for Fp<P, N> {
    fn from(other: bool) -> Self {
        todo!()
    }
}

////////////////////////////////////////////////////////////////////////////
// Field
////////////////////////////////////////////////////////////////////////////

// TODO one needs to implement these traits:
//
//    + Neg<Output = Self>
//    + UniformRand
//    + Zeroize
//    + CanonicalSerializeWithFlags
//    + CanonicalDeserializeWithFlags
//    + Sub<Self, Output = Self>
//    + Div<Self, Output = Self>
//    + AddAssign<Self>
//    + SubAssign<Self>
//    + MulAssign<Self>
//    + DivAssign<Self>
//    + for<'a> Sub<&'a Self, Output = Self>
//    + for<'a> Div<&'a Self, Output = Self>
//    + for<'a> SubAssign<&'a Self>
//    + for<'a> DivAssign<&'a Self>
//    + for<'a> Add<&'a mut Self, Output = Self>
//    + for<'a> Sub<&'a mut Self, Output = Self>
//    + for<'a> Mul<&'a mut Self, Output = Self>
//    + for<'a> Div<&'a mut Self, Output = Self>
//    + for<'a> AddAssign<&'a mut Self>
//    + for<'a> SubAssign<&'a mut Self>
//    + for<'a> MulAssign<&'a mut Self>
//    + for<'a> DivAssign<&'a mut Self>
//    + core::iter::Sum<Self>
//    + for<'a> core::iter::Sum<&'a Self>
//    + core::iter::Product<Self>
//    + for<'a> core::iter::Product<&'a Self>

impl<P: FpBackend<N>, const N: usize> PrimeField for Fp<P, N> {
    type BigInt = BigInt<N>;
    const MODULUS: Self::BigInt = P::MODULUS;
    const MODULUS_MINUS_ONE_DIV_TWO: Self::BigInt = P::MODULUS.divide_by_2_round_down();
    const MODULUS_BIT_SIZE: u32 = P::MODULUS.const_num_bits();
    const TRACE: Self::BigInt = P::MODULUS.two_adic_coefficient();
    const TRACE_MINUS_ONE_DIV_TWO: Self::BigInt = Self::TRACE.divide_by_2_round_down();

    #[inline]
    fn from_bigint(r: BigInt<N>) -> Option<Self> {
        todo!()
        //P::from_bigint(r)
    }

    fn into_bigint(self) -> BigInt<N> {
        todo!()
        //P::into_bigint(self)
    }
}

impl<P: FpBackend<N>, const N: usize> FftField for Fp<P, N> {
    const GENERATOR: Self = Fp(P::MODULUS, PhantomData);
    const TWO_ADICITY: u32 = 0; // FIXME!!! // P::TWO_ADICITY;
    const TWO_ADIC_ROOT_OF_UNITY: Self = Fp(P::ZERO, PhantomData); // FIXME //P::TWO_ADIC_ROOT_OF_UNITY;
    const SMALL_SUBGROUP_BASE: Option<u32> = None; //FIXME!! // P::SMALL_SUBGROUP_BASE;
    const SMALL_SUBGROUP_BASE_ADICITY: Option<u32> = None; // FIXME! // P::SMALL_SUBGROUP_BASE_ADICITY;
    const LARGE_SUBGROUP_ROOT_OF_UNITY: Option<Self> = None; // FIXME! //P::LARGE_SUBGROUP_ROOT_OF_UNITY;
}

impl<P: FpBackend<N>, const N: usize> AdditiveGroup for Fp<P, N> {
    type Scalar = Self;
    const ZERO: Self = Fp(P::ZERO, PhantomData);

    #[inline]
    fn double(&self) -> Self {
        let mut temp = *self;
        temp.double_in_place();
        temp
    }

    #[inline]
    fn double_in_place(&mut self) -> &mut Self {
        todo!()
        //P::double_in_place(self);
        //self
    }

    #[inline]
    fn neg_in_place(&mut self) -> &mut Self {
        todo!()
        //P::neg_in_place(self);
        //self
    }
}

impl<P: FpBackend<N>, const N: usize> Field for Fp<P, N> {
    type BasePrimeField = Self;

    const SQRT_PRECOMP: Option<ark_ff::SqrtPrecomputation<Self>> = None; // FIXME //P::SQRT_PRECOMP;
    const ONE: Self = Fp(P::ONE, PhantomData);

    fn extension_degree() -> u64 {
        1
    }

    fn from_base_prime_field(elem: Self::BasePrimeField) -> Self {
        elem
    }

    fn to_base_prime_field_elements(&self) -> core::iter::Once<Self::BasePrimeField> {
        core::iter::once(*self)
    }

    fn from_base_prime_field_elems(
        elems: impl IntoIterator<Item = Self::BasePrimeField>,
    ) -> Option<Self> {
        todo!()
        //        if elems.len() != (Self::extension_degree() as usize) {
        //            return None;
        //        }
        //        Some(elems[0])
    }

    #[inline]
    fn characteristic() -> &'static [u64] {
        P::MODULUS.as_ref()
    }

    #[inline]
    fn sum_of_products<const T: usize>(a: &[Self; T], b: &[Self; T]) -> Self {
        todo!()
        //P::sum_of_products(a, b)
    }

    #[inline]
    fn from_random_bytes_with_flags<F: Flags>(bytes: &[u8]) -> Option<(Self, F)> {
        todo!()
        //if F::BIT_SIZE > 8 {
        //    None
        //} else {
        //    let shave_bits = Self::num_bits_to_shave();
        //    let mut result_bytes = crate::const_helpers::SerBuffer::<N>::zeroed();
        //    // Copy the input into a temporary buffer.
        //    result_bytes.copy_from_u8_slice(bytes);
        //    // This mask retains everything in the last limb
        //    // that is below `P::MODULUS_BIT_SIZE`.
        //    let last_limb_mask =
        //        (u64::MAX.checked_shr(shave_bits as u32).unwrap_or(0)).to_le_bytes();
        //    let mut last_bytes_mask = [0u8; 9];
        //    last_bytes_mask[..8].copy_from_slice(&last_limb_mask);

        //    // Length of the buffer containing the field element and the flag.
        //    let output_byte_size = buffer_byte_size(Self::MODULUS_BIT_SIZE as usize + F::BIT_SIZE);
        //    // Location of the flag is the last byte of the serialized
        //    // form of the field element.
        //    let flag_location = output_byte_size - 1;

        //    // At which byte is the flag located in the last limb?
        //    let flag_location_in_last_limb = flag_location.saturating_sub(8 * (N - 1));

        //    // Take all but the last 9 bytes.
        //    let last_bytes = result_bytes.last_n_plus_1_bytes_mut();

        //    // The mask only has the last `F::BIT_SIZE` bits set
        //    let flags_mask = u8::MAX.checked_shl(8 - (F::BIT_SIZE as u32)).unwrap_or(0);

        //    // Mask away the remaining bytes, and try to reconstruct the
        //    // flag
        //    let mut flags: u8 = 0;
        //    for (i, (b, m)) in last_bytes.zip(&last_bytes_mask).enumerate() {
        //        if i == flag_location_in_last_limb {
        //            flags = *b & flags_mask
        //        }
        //        *b &= m;
        //    }
        //    Self::deserialize_compressed(&result_bytes.as_slice()[..(N * 8)])
        //        .ok()
        //        .and_then(|f| F::from_u8(flags).map(|flag| (f, flag)))
        //}
    }

    #[inline]
    fn square(&self) -> Self {
        todo!()
        //let mut temp = *self;
        //temp.square_in_place();
        //temp
    }

    fn square_in_place(&mut self) -> &mut Self {
        todo!()
        //P::square_in_place(self);
        //self
    }

    #[inline]
    fn inverse(&self) -> Option<Self> {
        todo!()
        //P::inverse(self)
    }

    fn inverse_in_place(&mut self) -> Option<&mut Self> {
        if let Some(inverse) = self.inverse() {
            *self = inverse;
            Some(self)
        } else {
            None
        }
    }

    /// The Frobenius map has no effect in a prime field.
    #[inline]
    fn frobenius_map_in_place(&mut self, _: usize) {}

    #[inline]
    fn legendre(&self) -> ark_ff::LegendreSymbol {
        todo!()
        //use crate::fields::LegendreSymbol::*;

        //// s = self^((MODULUS - 1) // 2)
        //let s = self.pow(Self::MODULUS_MINUS_ONE_DIV_TWO);
        //if s.is_zero() {
        //    Zero
        //} else if s.is_one() {
        //    QuadraticResidue
        //} else {
        //    QuadraticNonResidue
        //}
    }

    fn mul_by_base_prime_field(&self, elem: &Self::BasePrimeField) -> Self {
        todo!()
    }
}

//impl<P: FpBackend<N>, const N: usize> Field for Fp<P, N> {
//    type BasePrimeField = Self;
//    fn extension_degree() -> u64 {
//        1
//    }
//    fn from_base_prime_field_elems(elems: &[Self::BasePrimeField]) -> Option<Self> {
//        todo!()
//        //if elems.len() != (Self::extension_degree() as usize) {
//        //    return None;
//        //}
//        //Some(elems[0])
//    }
//    #[inline]
//    fn double(&self) -> Self {
//        todo!()
//        //let mut temp = *self;
//        //temp.double_in_place();
//        //temp
//    }
//    #[inline]
//    fn double_in_place(&mut self) -> &mut Self {
//        todo!()
//        //self.0.mul2();
//        //self.reduce();
//        //self
//    }
//    #[inline]
//    fn characteristic() -> [u64; 4] {
//        todo!()
//        //C::MODULUS.to_64x4()
//    }
//    #[inline]
//    fn from_random_bytes_with_flags<F: Flags>(bytes: &[u8]) -> Option<(Self, F)> {
//        todo!()
//        //if F::BIT_SIZE > 8 {
//        //    return None;
//        //} else {
//        //    let mut result_bytes = [0u8; 4 * 8 + 1];
//        //    result_bytes
//        //        .iter_mut()
//        //        .zip(bytes)
//        //        .for_each(|(result, input)| {
//        //            *result = *input;
//        //        });
//        //    let last_limb_mask = (u64::MAX >> C::REPR_SHAVE_BITS).to_le_bytes();
//        //    let mut last_bytes_mask = [0u8; 9];
//        //    last_bytes_mask[..8].copy_from_slice(&last_limb_mask);
//        //    let output_byte_size = buffer_byte_size(C::MODULUS_BITS as usize + F::BIT_SIZE);
//        //    let flag_location = output_byte_size - 1;
//        //    let flag_location_in_last_limb = flag_location - (8 * (4 - 1));
//        //    let last_bytes = &mut result_bytes[8 * (4 - 1)..];
//        //    let flags_mask = u8::MAX.checked_shl(8 - (F::BIT_SIZE as u32)).unwrap_or(0);
//        //    let mut flags: u8 = 0;
//        //    for (i, (b, m)) in last_bytes.iter_mut().zip(&last_bytes_mask).enumerate() {
//        //        if i == flag_location_in_last_limb {
//        //            flags = *b & flags_mask;
//        //        }
//        //        *b &= m;
//        //    }
//        //    Self::deserialize(&result_bytes[..(4 * 8)])
//        //        .ok()
//        //        .and_then(|f| F::from_u8(flags).map(|flag| (f, flag)))
//        //}
//    }
//    #[inline(always)]
//    fn square(&self) -> Self {
//        todo!()
//        //let mut temp = self.clone();
//        //temp.square_in_place();
//        //temp
//    }
//    #[inline(always)]
//    fn square_in_place(&mut self) -> &mut Self {
//        todo!()
//        //self.const_square();
//        //self
//    }
//    #[inline]
//    fn inverse(&self) -> Option<Self> {
//        todo!()
//        //if self.is_zero() {
//        //    None
//        //} else {
//        //    let one = BigInteger256::from(1);
//        //    let mut u = self.0;
//        //    let mut v = C::MODULUS;
//        //    let mut b = Self(C::R2, PhantomData);
//        //    let mut c = Self::zero();
//        //    while u != one && v != one {
//        //        while u.is_even() {
//        //            u.div2();
//        //            if b.0.is_even() {
//        //                b.0.div2();
//        //            } else {
//        //                b.0.add_nocarry(&C::MODULUS);
//        //                b.0.div2();
//        //            }
//        //        }
//        //        while v.is_even() {
//        //            v.div2();
//        //            if c.0.is_even() {
//        //                c.0.div2();
//        //            } else {
//        //                c.0.add_nocarry(&C::MODULUS);
//        //                c.0.div2();
//        //            }
//        //        }
//        //        if v < u {
//        //            u.sub_noborrow(&v);
//        //            b.sub_assign(&c);
//        //        } else {
//        //            v.sub_noborrow(&u);
//        //            c.sub_assign(&b);
//        //        }
//        //    }
//        //    if u == one {
//        //        Some(b)
//        //    } else {
//        //        Some(c)
//        //    }
//        //}
//    }
//    fn inverse_in_place(&mut self) -> Option<&mut Self> {
//        if let Some(inverse) = self.inverse() {
//            *self = inverse;
//            Some(self)
//        } else {
//            None
//        }
//    }
//    #[inline]
//    fn frobenius_map(&mut self, _: usize) {
//        todo!()
//    }
//}
