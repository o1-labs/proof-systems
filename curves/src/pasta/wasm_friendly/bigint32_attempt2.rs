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
        BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign, Shl, ShlAssign, Shr,
        ShrAssign,
    },
    str::FromStr,
};
use num_bigint::BigUint;
use zeroize::Zeroize;

use bnum::{errors::ParseIntError, BUintD32};

#[derive(Copy, Clone, PartialEq, Eq, Debug, Hash)]
pub struct BigInt<const N: usize>(pub BUintD32<N>);

impl<const N: usize> BigInt<N> {
    pub const ZERO: Self = BigInt(BUintD32::ZERO);

    pub const fn from_digits(digits: [u32; N]) -> Self {
        BigInt(BUintD32::from_digits(digits))
    }

    /// Compute the smallest odd integer `t` such that `self = 2**s * t + 1` for some
    /// integer `s = self.two_adic_valuation()`.
    #[doc(hidden)]
    pub const fn two_adic_coefficient(mut self) -> Self {
        todo!()
    }

    /// Divide `self` by 2, rounding down if necessary.
    /// That is, if `self.is_odd()`, compute `(self - 1)/2`.
    /// Else, compute `self/2`.
    #[doc(hidden)]
    pub const fn divide_by_2_round_down(mut self) -> Self {
        todo!()
    }

    /// Find the number of bits in the binary decomposition of `self`.
    #[doc(hidden)]
    pub const fn const_num_bits(self) -> u32 {
        todo!()
    }

    #[inline]
    pub fn add_nocarry(&mut self, other: &Self) -> bool {
        todo!()
        //let mut this = self.to_64x4();
        //let other = other.to_64x4();

        //let mut carry = 0;
        //for i in 0..4 {
        //    this[i] = adc!(this[i], other[i], &mut carry);
        //}
        //*self = Self::from_64x4(this);
        //carry != 0
    }

    #[inline]
    pub fn sub_noborrow(&mut self, other: &Self) -> bool {
        todo!()
        //let mut this = self.to_64x4();
        //let other = other.to_64x4();

        //let mut borrow = 0;
        //for i in 0..4 {
        //    this[i] = sbb!(this[i], other[i], &mut borrow);
        //}
        //*self = Self::from_64x4(this);
        //borrow != 0
    }
}

impl<const N: usize> Zeroize for BigInt<N> {
    fn zeroize(&mut self) {
        self.0 = BUintD32::ZERO;
    }
}

impl<const N: usize> AsMut<[u64]> for BigInt<N> {
    #[inline]
    fn as_mut(&mut self) -> &mut [u64] {
        todo!()
    }
}

impl<const N: usize> AsRef<[u64]> for BigInt<N> {
    #[inline]
    fn as_ref(&self) -> &[u64] {
        todo!()
    }
}

impl<const N: usize> From<u64> for BigInt<N> {
    #[inline]
    fn from(val: u64) -> BigInt<N> {
        todo!()
    }
}

impl<const N: usize> From<u32> for BigInt<N> {
    #[inline]
    fn from(val: u32) -> BigInt<N> {
        todo!()
    }
}

impl<const N: usize> From<u16> for BigInt<N> {
    #[inline]
    fn from(val: u16) -> BigInt<N> {
        todo!()
    }
}

impl<const N: usize> From<u8> for BigInt<N> {
    #[inline]
    fn from(val: u8) -> BigInt<N> {
        todo!()
    }
}

impl<const N: usize> TryFrom<BigUint> for BigInt<N> {
    type Error = ();

    /// Returns `Err(())` if the bit size of `val` is more than `N * 64`.
    #[inline]
    fn try_from(val: num_bigint::BigUint) -> Result<BigInt<N>, Self::Error> {
        todo!()
        //let bytes = val.to_bytes_le();

        //if bytes.len() > N * 8 {
        //    Err(())
        //} else {
        //    let mut limbs = [0u64; N];

        //    bytes
        //        .chunks(8)
        //        .into_iter()
        //        .enumerate()
        //        .for_each(|(i, chunk)| {
        //            let mut chunk_padded = [0u8; 8];
        //            chunk_padded[..chunk.len()].copy_from_slice(chunk);
        //            limbs[i] = u64::from_le_bytes(chunk_padded)
        //        });

        //    Ok(Self(limbs))
        //}
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
        todo!()
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
        todo!()
        //let mut res = [0u64; N];
        //for item in res.iter_mut() {
        //    *item = rng.gen();
        //}
        //BigInt::<N>(res)
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

impl<const N: usize> BigInteger for BigInt<N> {
    const NUM_LIMBS: usize = N;

    #[inline]
    fn add_with_carry(&mut self, other: &Self) -> bool {
        todo!();
    }

    #[inline]
    fn sub_with_borrow(&mut self, other: &Self) -> bool {
        todo!()
    }

    #[inline]
    #[allow(unused)]
    fn mul2(&mut self) -> bool {
        todo!()
    }

    #[inline]
    fn mul(&self, other: &Self) -> (Self, Self) {
        todo!()
    }

    #[inline]
    fn mul_low(&self, other: &Self) -> Self {
        todo!()
    }

    #[inline]
    fn mul_high(&self, other: &Self) -> Self {
        todo!()
    }

    #[inline]
    fn muln(&mut self, mut n: u32) {
        todo!()
    }

    #[inline]
    fn div2(&mut self) {
        todo!()
    }

    #[inline]
    fn divn(&mut self, mut n: u32) {
        todo!()
    }

    #[inline]
    fn is_odd(&self) -> bool {
        todo!()
    }

    #[inline]
    fn is_even(&self) -> bool {
        todo!()
    }

    #[inline]
    fn is_zero(&self) -> bool {
        todo!()
    }

    #[inline]
    fn num_bits(&self) -> u32 {
        todo!()
    }

    #[inline]
    fn get_bit(&self, i: usize) -> bool {
        todo!()
    }

    #[inline]
    fn from_bits_be(bits: &[bool]) -> Self {
        todo!()
        //let mut res = Self::default();
        //let mut acc: u64 = 0;

        //let mut bits = bits.to_vec();
        //bits.reverse();
        //for (i, bits64) in bits.chunks(64).enumerate() {
        //    for bit in bits64.iter().rev() {
        //        acc <<= 1;
        //        acc += *bit as u64;
        //    }
        //    res.0[i] = acc;
        //    acc = 0;
        //}
        //res
    }

    fn from_bits_le(bits: &[bool]) -> Self {
        todo!()
        //let mut res = Self::zero();
        //for (bits64, res_i) in bits.chunks(64).zip(&mut res.0) {
        //    for (i, bit) in bits64.iter().enumerate() {
        //        *res_i |= (*bit as u64) << i;
        //    }
        //}
        //res
    }

    #[inline]
    fn to_bytes_be(&self) -> Vec<u8> {
        todo!()
    }

    #[inline]
    fn to_bytes_le(&self) -> Vec<u8> {
        todo!()
    }
}

impl<const N: usize> Into<[u32; N]> for BigInt<N> {
    #[inline]
    fn into(self) -> [u32; N] {
        *self.0.digits()
    }
}
