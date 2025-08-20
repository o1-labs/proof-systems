use ark_ff::BigInteger;
use ark_serialize::{
    CanonicalDeserialize, CanonicalSerialize, Compress, Read, SerializationError, Valid, Validate,
    Write,
};
use ark_std::{
    fmt::Display,
    rand::{
        distributions::{Distribution, Standard},
        Rng,
    },
};
use core::{
    ops::{
        Add, BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign, Mul, Shl, ShlAssign,
        Shr, ShrAssign,
    },
    str::FromStr,
};
use num_bigint::BigUint;
use std::ops::Rem;
use zeroize::Zeroize;

use bnum::{errors::ParseIntError, BUintD32};

/// Digits inside are stored in little endian
#[derive(Copy, Clone, PartialEq, Eq, Debug, Hash)]
pub struct BigInt<const N: usize>(pub BUintD32<N>);

impl<const N: usize> BigInt<N> {
    pub const ZERO: Self = BigInt(BUintD32::ZERO);
    pub const ONE: Self = BigInt(BUintD32::ONE);
    pub const FIVE: Self = BigInt(BUintD32::FIVE);

    /// Returns limbs in little endian
    pub const fn from_digits(digits: [u32; N]) -> Self {
        BigInt(BUintD32::from_digits(digits))
    }

    /// Returns limbs in little endian
    pub const fn into_digits(self) -> [u32; N] {
        *self.0.digits()
    }

    #[inline]
    pub fn as_digits_mut(&mut self) -> &mut [u32; N] {
        self.0.digits_mut()
    }

    #[doc(hidden)]
    pub const fn const_is_even(&self) -> bool {
        self.0.digits()[0] % 2 == 0
    }

    #[doc(hidden)]
    pub const fn const_is_odd(&self) -> bool {
        self.0.digits()[0] % 2 == 1
    }

    /// Compute a right shift of `self`
    /// This is equivalent to a (saturating) division by 2.
    #[doc(hidden)]
    pub const fn const_shr(&self) -> Self {
        BigInt(self.0.unbounded_shr(1))
    }

    /// Compute the smallest odd integer `t` such that `self = 2**s * t + 1` for some
    /// integer `s = self.two_adic_valuation()`.
    #[doc(hidden)]
    pub const fn two_adic_coefficient(mut self) -> Self {
        assert!(self.const_is_odd());
        // Since `self` is odd, we can always subtract one
        // without a borrow
        self.const_shr();
        while self.const_is_even() {
            self = self.const_shr();
        }
        assert!(self.const_is_odd());
        self
    }

    /// Divide `self` by 2, rounding down if necessary.
    /// That is, if `self.is_odd()`, compute `(self - 1)/2`.
    /// Else, compute `self/2`.
    #[doc(hidden)]
    pub const fn divide_by_2_round_down(self) -> Self {
        BigInt(self.0.unbounded_shr(1))
    }

    /// Find the number of bits in the binary decomposition of `self`.
    #[doc(hidden)]
    pub const fn const_num_bits(self) -> u32 {
        self.0.bits()
    }

    #[inline]
    pub fn add_nocarry(&mut self, other: &Self) -> bool {
        let (new, res) = self.0.carrying_add(other.0, false);
        self.0 = new;
        res
    }

    #[inline]
    pub fn sub_noborrow(&mut self, other: &Self) -> bool {
        let (new, res) = self.0.borrowing_sub(other.0, false);
        self.0 = new;
        res
    }
}

impl<const N: usize> Zeroize for BigInt<N> {
    fn zeroize(&mut self) {
        self.0 = BUintD32::ZERO;
    }
}

// @volhovm: this is incredibly sketchy. The interface of Integer
// itself (in arkworks) does not allow 32-bit integers... what the
// hell.
impl<const N: usize> AsMut<[u64]> for BigInt<N> {
    #[inline]
    fn as_mut(&mut self) -> &mut [u64] {
        assert!(
            N % 2 == 0,
            "N must be even to convert u32 array to u64 array"
        );
        unsafe {
            std::slice::from_raw_parts_mut(self.0.digits_mut().as_mut_ptr() as *mut u64, N / 2)
        }
    }
}

impl<const N: usize> AsRef<[u64]> for BigInt<N> {
    #[inline]
    fn as_ref(&self) -> &[u64] {
        assert!(
            N % 2 == 0,
            "N must be even to convert u32 array to u64 array"
        );
        unsafe { std::slice::from_raw_parts(self.0.digits().as_ptr() as *const u64, N / 2) }
    }
}

impl<const N: usize> AsMut<[u32]> for BigInt<N> {
    #[inline]
    fn as_mut(&mut self) -> &mut [u32] {
        self.0.digits_mut()
    }
}

impl<const N: usize> AsRef<[u32]> for BigInt<N> {
    #[inline]
    fn as_ref(&self) -> &[u32] {
        self.0.digits()
    }
}

impl<const N: usize> From<u128> for BigInt<N> {
    #[inline]
    fn from(val: u128) -> BigInt<N> {
        BigInt(BUintD32::from(val))
    }
}

impl<const N: usize> From<u64> for BigInt<N> {
    #[inline]
    fn from(val: u64) -> BigInt<N> {
        BigInt(BUintD32::from(val))
    }
}

impl<const N: usize> From<u32> for BigInt<N> {
    #[inline]
    fn from(val: u32) -> BigInt<N> {
        BigInt(BUintD32::from(val))
    }
}

impl<const N: usize> From<u16> for BigInt<N> {
    #[inline]
    fn from(val: u16) -> BigInt<N> {
        BigInt(BUintD32::from(val))
    }
}

impl<const N: usize> From<u8> for BigInt<N> {
    #[inline]
    fn from(val: u8) -> BigInt<N> {
        BigInt(BUintD32::from(val))
    }
}

impl<const N: usize> TryFrom<BigUint> for BigInt<N> {
    type Error = ();

    /// Returns `Err(())` if the bit size of `val` is more than `N * 64`.
    #[inline]
    fn try_from(val: num_bigint::BigUint) -> Result<BigInt<N>, Self::Error> {
        todo!()
    }
}

impl<const N: usize> From<BigInt<N>> for BigUint {
    #[inline]
    fn from(val: BigInt<N>) -> num_bigint::BigUint {
        BigUint::from_bytes_le(&val.to_bytes_le())
    }
}

impl<const N: usize> Default for BigInt<N> {
    fn default() -> Self {
        Self(BUintD32::ZERO)
    }
}

impl<const N: usize> CanonicalSerialize for BigInt<N> {
    fn serialize_with_mode<W: Write>(
        &self,
        writer: W,
        compress: Compress,
    ) -> Result<(), SerializationError> {
        todo!()
    }

    fn serialized_size(&self, compress: Compress) -> usize {
        todo!()
    }
}

impl<const N: usize> Valid for BigInt<N> {
    fn check(&self) -> Result<(), SerializationError> {
        todo!()
    }
}

impl<const N: usize> CanonicalDeserialize for BigInt<N> {
    fn deserialize_with_mode<R: Read>(
        reader: R,
        compress: Compress,
        validate: Validate,
    ) -> Result<Self, SerializationError> {
        todo!()
    }
}

impl<const N: usize> Ord for BigInt<N> {
    #[inline]
    fn cmp(&self, other: &Self) -> ::core::cmp::Ordering {
        self.0.cmp(&other.0)
    }
}

impl<const N: usize> PartialOrd for BigInt<N> {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<::core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<const N: usize> Display for BigInt<N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", BigUint::from(*self))
    }
}

impl<const N: usize> Distribution<BigInt<N>> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> BigInt<N> {
        let mut res = [0u32; N];
        for item in res.iter_mut() {
            *item = rng.gen();
        }
        BigInt::from_digits(res)
    }
}

// do not use forward_ref_ref_binop_commutative! for bitand so that we can
// clone as needed, avoiding over-allocation
impl<const N: usize> BitAnd<&BigInt<N>> for &BigInt<N> {
    type Output = BigInt<N>;

    #[inline]
    fn bitand(self, other: &BigInt<N>) -> BigInt<N> {
        BigInt(self.0.bitand(other.0))
    }
}

impl<const N: usize> BitAnd<&BigInt<N>> for BigInt<N> {
    type Output = BigInt<N>;

    #[inline]
    fn bitand(self, other: &BigInt<N>) -> BigInt<N> {
        BigInt(self.0.bitand(other.0))
    }
}

impl<const N: usize> BitAnd<BigInt<N>> for &BigInt<N> {
    type Output = BigInt<N>;

    #[inline]
    fn bitand(self, other: BigInt<N>) -> BigInt<N> {
        BigInt(self.0.bitand(other.0))
    }
}

impl<const N: usize> BitAnd<BigInt<N>> for BigInt<N> {
    type Output = BigInt<N>;

    #[inline]
    fn bitand(self, other: BigInt<N>) -> BigInt<N> {
        BigInt(self.0.bitand(other.0))
    }
}

impl<const N: usize> BitAndAssign<BigInt<N>> for BigInt<N> {
    fn bitand_assign(&mut self, other: BigInt<N>) {
        self.0.bitand_assign(other.0)
    }
}

impl<const N: usize> BitAndAssign<&BigInt<N>> for BigInt<N> {
    fn bitand_assign(&mut self, other: &BigInt<N>) {
        self.0.bitand_assign(other.0)
    }
}

impl<const N: usize> BitOr<BigInt<N>> for &BigInt<N> {
    type Output = BigInt<N>;

    #[inline]
    fn bitor(self, other: BigInt<N>) -> BigInt<N> {
        BigInt(self.0.bitor(other.0))
    }
}

impl<const N: usize> BitOr<&BigInt<N>> for &BigInt<N> {
    type Output = BigInt<N>;

    #[inline]
    fn bitor(self, other: &BigInt<N>) -> BigInt<N> {
        BigInt(self.0.bitor(other.0))
    }
}

impl<const N: usize> BitOr<&BigInt<N>> for BigInt<N> {
    type Output = BigInt<N>;

    #[inline]
    fn bitor(self, other: &BigInt<N>) -> BigInt<N> {
        BigInt(self.0.bitor(other.0))
    }
}

impl<const N: usize> BitOr<BigInt<N>> for BigInt<N> {
    type Output = BigInt<N>;

    #[inline]
    fn bitor(self, other: BigInt<N>) -> BigInt<N> {
        BigInt(self.0.bitor(other.0))
    }
}

impl<const N: usize> BitOrAssign<BigInt<N>> for BigInt<N> {
    fn bitor_assign(&mut self, other: BigInt<N>) {
        self.0.bitor_assign(other.0)
    }
}

impl<const N: usize> BitOrAssign<&BigInt<N>> for BigInt<N> {
    fn bitor_assign(&mut self, other: &BigInt<N>) {
        self.0.bitor_assign(other.0)
    }
}

impl<const N: usize> Shl<u32> for BigInt<N> {
    type Output = BigInt<N>;

    #[inline]
    fn shl(self, rhs: u32) -> BigInt<N> {
        BigInt(self.0.shl(rhs))
    }
}
impl<const N: usize> Shl<u32> for &BigInt<N> {
    type Output = BigInt<N>;

    #[inline]
    fn shl(self, rhs: u32) -> BigInt<N> {
        BigInt(self.0.shl(rhs))
    }
}
impl<const N: usize> ShlAssign<u32> for BigInt<N> {
    #[inline]
    fn shl_assign(&mut self, rhs: u32) {
        self.0.shl_assign(rhs)
    }
}

impl<const N: usize> Shr<u32> for BigInt<N> {
    type Output = BigInt<N>;

    #[inline]
    fn shr(self, rhs: u32) -> BigInt<N> {
        BigInt(self.0.shr(rhs))
    }
}
impl<const N: usize> Shr<u32> for &BigInt<N> {
    type Output = BigInt<N>;

    #[inline]
    fn shr(self, rhs: u32) -> BigInt<N> {
        BigInt(self.0.shr(rhs))
    }
}
impl<const N: usize> ShrAssign<u32> for BigInt<N> {
    #[inline]
    fn shr_assign(&mut self, rhs: u32) {
        self.0.shr_assign(rhs)
    }
}

impl<const N: usize> BitXor<&BigInt<N>> for BigInt<N> {
    type Output = BigInt<N>;

    #[inline]
    fn bitxor(self, other: &BigInt<N>) -> BigInt<N> {
        BigInt(self.0.bitxor(other.0))
    }
}

impl<const N: usize> BitXor<BigInt<N>> for BigInt<N> {
    type Output = BigInt<N>;

    #[inline]
    fn bitxor(self, other: BigInt<N>) -> BigInt<N> {
        BigInt(self.0.bitxor(other.0))
    }
}

impl<const N: usize> BitXorAssign<BigInt<N>> for BigInt<N> {
    fn bitxor_assign(&mut self, other: BigInt<N>) {
        self.0.bitxor_assign(other.0)
    }
}

impl<const N: usize> BitXorAssign<&BigInt<N>> for BigInt<N> {
    fn bitxor_assign(&mut self, other: &BigInt<N>) {
        self.0.bitxor_assign(other.0)
    }
}

impl<const N: usize> FromStr for BigInt<N> {
    type Err = ParseIntError;

    #[inline]
    fn from_str(s: &str) -> Result<BigInt<N>, Self::Err> {
        let inner = BUintD32::<N>::from_str(s)?;
        // Wrap it in your BigInt newtype
        Ok(BigInt(inner))
    }
}

impl<const N: usize> Add<BigInt<N>> for BigInt<N> {
    type Output = BigInt<N>;

    #[inline]
    fn add(self, rhs: BigInt<N>) -> BigInt<N> {
        BigInt(self.0 + &rhs.0)
    }
}

impl<const N: usize> Add<&BigInt<N>> for BigInt<N> {
    type Output = BigInt<N>;

    #[inline]
    fn add(self, rhs: &BigInt<N>) -> BigInt<N> {
        BigInt(self.0 + &rhs.0)
    }
}

impl<const N: usize> Mul<BigInt<N>> for BigInt<N> {
    type Output = BigInt<N>;

    #[inline]
    fn mul(self, rhs: BigInt<N>) -> BigInt<N> {
        BigInt(self.0 * &rhs.0)
    }
}

impl<const N: usize> Mul<&BigInt<N>> for BigInt<N> {
    type Output = BigInt<N>;

    #[inline]
    fn mul(self, rhs: &BigInt<N>) -> BigInt<N> {
        BigInt(self.0 * &rhs.0)
    }
}

impl<const N: usize> Rem<BigInt<N>> for BigInt<N> {
    type Output = BigInt<N>;

    #[inline]
    fn rem(self, rhs: BigInt<N>) -> BigInt<N> {
        BigInt(self.0.rem_euclid(rhs.0))
    }
}

impl<const N: usize> Rem<&BigInt<N>> for BigInt<N> {
    type Output = BigInt<N>;

    #[inline]
    fn rem(self, rhs: &BigInt<N>) -> BigInt<N> {
        BigInt(self.0.rem_euclid(rhs.0))
    }
}

impl<const N: usize> BigInteger for BigInt<N> {
    const NUM_LIMBS: usize = N;

    #[inline]
    fn add_with_carry(&mut self, other: &Self) -> bool {
        let (new, res) = self.0.carrying_add(other.0, false);
        self.0 = new;
        res
    }

    #[inline]
    fn sub_with_borrow(&mut self, other: &Self) -> bool {
        let (new, res) = self.0.borrowing_sub(other.0, false);
        self.0 = new;
        res
    }

    #[inline]
    #[allow(unused)]
    fn mul2(&mut self) -> bool {
        self.0.shr_assign(1);
        true // FIXME should this be the shifted bit?
    }

    #[inline]
    fn muln(&mut self, n: u32) {
        self.0.shr_assign(n);
    }

    #[inline]
    fn mul_low(&self, other: &Self) -> Self {
        let (low, _) = self.0.widening_mul(other.0);
        BigInt(low)
    }

    #[inline]
    fn mul_high(&self, other: &Self) -> Self {
        let (_, high) = self.0.widening_mul(other.0);
        BigInt(high)
    }

    #[inline]
    fn mul(&self, other: &Self) -> (Self, Self) {
        let (low, high) = self.0.widening_mul(other.0);
        (BigInt(low), BigInt(high))
    }

    #[inline]
    fn div2(&mut self) {
        self.0 /= BUintD32::from(2u32);
    }

    #[inline]
    fn divn(&mut self, n: u32) {
        self.0 /= BUintD32::from(n);
    }

    #[inline]
    fn is_odd(&self) -> bool {
        !self.0.rem_euclid(BUintD32::from(2u32)).is_zero()
    }

    #[inline]
    fn is_even(&self) -> bool {
        self.0.rem_euclid(BUintD32::from(2u32)).is_zero()
    }

    #[inline]
    fn is_zero(&self) -> bool {
        self.0.is_zero()
    }

    #[inline]
    fn num_bits(&self) -> u32 {
        self.0.bits()
    }

    #[inline]
    fn get_bit(&self, i: usize) -> bool {
        self.0.bit(i as u32)
    }

    #[inline]
    fn from_bits_be(bits: &[bool]) -> Self {
        // FIXME check this works
        let mut bytes = vec![];
        for chunk in bits.chunks(8) {
            let mut byte = 0u8;
            for (i, &bit) in chunk.iter().enumerate() {
                if bit {
                    byte |= 1 << (7 - i); // For big-endian, MSB is first
                }
            }
            bytes.push(byte);
        }
        BigInt(BUintD32::from_be_slice(&bytes).unwrap())
    }

    #[inline]
    fn from_bits_le(bits: &[bool]) -> Self {
        // FIXME check this works
        let mut bytes = vec![];
        for chunk in bits.chunks(8) {
            let mut byte = 0u8;
            for (i, &bit) in chunk.iter().enumerate() {
                if bit {
                    byte |= 1 << i; // For little-endian, LSB is first
                }
            }
            bytes.push(byte);
        }
        BigInt(BUintD32::from_le_slice(&bytes).unwrap())
    }

    #[inline]
    fn to_bytes_be(&self) -> Vec<u8> {
        // digits() are little endian
        let digits: &[u32; N] = self.0.digits();
        let mut bytes = Vec::with_capacity(4 * N);

        for &digit in digits.iter().rev() {
            bytes.push((digit >> 24) as u8);
            bytes.push((digit >> 16) as u8);
            bytes.push((digit >> 8) as u8);
            bytes.push(digit as u8);
        }

        bytes
    }

    #[inline]
    fn to_bytes_le(&self) -> Vec<u8> {
        // digits() are little endian
        let digits: &[u32; N] = self.0.digits();
        let mut bytes = Vec::with_capacity(4 * N);

        for &digit in digits.iter() {
            bytes.push(digit as u8);
            bytes.push((digit >> 8) as u8);
            bytes.push((digit >> 16) as u8);
            bytes.push((digit >> 24) as u8);
        }

        bytes
    }
}

impl<const N: usize> Into<[u32; N]> for BigInt<N> {
    #[inline]
    fn into(self) -> [u32; N] {
        *self.0.digits()
    }
}
