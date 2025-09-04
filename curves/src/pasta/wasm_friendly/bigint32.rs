//!
//! BigInt with 32-bit limbs
//!
//! Contains everything for wasm_fp which is unrelated to being a field
//!
//! Code is mostly copied from ark-ff::BigInt
//!
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
use num_bigint::{BigUint, ParseBigIntError};
use zeroize::Zeroize;

#[derive(Copy, Clone, PartialEq, Eq, Debug, Hash, Zeroize)]
pub struct BigInt<const N: usize>(pub [u32; N]);

impl<const N: usize> BigInt<N> {
    pub const fn new(value: [u32; N]) -> Self {
        Self(value)
    }

    pub const fn zero() -> Self {
        Self([0u32; N])
    }

    pub const fn one() -> Self {
        let mut one = Self::zero();
        one.0[0] = 1;
        one
    }

    #[doc(hidden)]
    pub const fn const_is_even(&self) -> bool {
        self.0[0] % 2 == 0
    }

    #[doc(hidden)]
    pub const fn const_is_odd(&self) -> bool {
        self.0[0] % 2 == 1
    }

    #[doc(hidden)]
    pub const fn mod_4(&self) -> u8 {
        todo!()
        // To compute n % 4, we need to simply look at the
        // 2 least significant bits of n, and check their value mod 4.
        //(((self.0[0] << 62) >> 62) % 4) as u8
    }

    /// Compute a right shift of `self`
    /// This is equivalent to a (saturating) division by 2.
    #[doc(hidden)]
    pub const fn const_shr(&self) -> Self {
        todo!()
        //let mut result = *self;
        //let mut t = 0;
        //crate::const_for!((i in 0..N) {
        //    let a = result.0[N - i - 1];
        //    let t2 = a << 63;
        //    result.0[N - i - 1] >>= 1;
        //    result.0[N - i - 1] |= t;
        //    t = t2;
        //});
        //result
    }

    const fn const_geq(&self, _other: &Self) -> bool {
        todo!()
        //const_for!((i in 0..N) {
        //    let a = self.0[N - i - 1];
        //    let b = other.0[N - i - 1];
        //    if a < b {
        //        return false;
        //    } else if a > b {
        //        return true;
        //    }
        //});
        //true
    }

    /// Compute the smallest odd integer `t` such that `self = 2**s * t + 1` for some
    /// integer `s = self.two_adic_valuation()`.
    #[doc(hidden)]
    pub const fn two_adic_coefficient(mut self) -> Self {
        assert!(self.const_is_odd());
        // Since `self` is odd, we can always subtract one
        // without a borrow
        self.0[0] -= 1;
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
    pub const fn divide_by_2_round_down(mut self) -> Self {
        if self.const_is_odd() {
            self.0[0] -= 1;
        }
        self.const_shr()
    }

    /// Find the number of bits in the binary decomposition of `self`.
    #[doc(hidden)]
    pub const fn const_num_bits(self) -> u32 {
        ((N - 1) * 64) as u32 + (64 - self.0[N - 1].leading_zeros())
    }

    #[inline]
    pub fn add_nocarry(&mut self, _other: &Self) -> bool {
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
    pub fn sub_noborrow(&mut self, _other: &Self) -> bool {
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

impl<const N: usize> AsMut<[u64]> for BigInt<N> {
    #[inline]
    fn as_mut(&mut self) -> &mut [u64] {
        todo!()
        //&mut self.0
    }
}

impl<const N: usize> AsRef<[u64]> for BigInt<N> {
    #[inline]
    fn as_ref(&self) -> &[u64] {
        todo!()
        //&self.0
    }
}

impl<const N: usize> From<u64> for BigInt<N> {
    #[inline]
    fn from(_val: u64) -> BigInt<N> {
        todo!()
        //let mut repr = Self::default();
        //repr.0[0] = val;
        //repr
    }
}

impl<const N: usize> From<u32> for BigInt<N> {
    #[inline]
    fn from(val: u32) -> BigInt<N> {
        let mut repr = Self::default();
        repr.0[0] = u32::from(val);
        repr
    }
}

impl<const N: usize> From<u16> for BigInt<N> {
    #[inline]
    fn from(val: u16) -> BigInt<N> {
        let mut repr = Self::default();
        repr.0[0] = u32::from(val);
        repr
    }
}

impl<const N: usize> From<u8> for BigInt<N> {
    #[inline]
    fn from(val: u8) -> BigInt<N> {
        let mut repr = Self::default();
        repr.0[0] = u32::from(val);
        repr
    }
}

impl<const N: usize> TryFrom<BigUint> for BigInt<N> {
    type Error = ();

    /// Returns `Err(())` if the bit size of `val` is more than `N * 64`.
    #[inline]
    fn try_from(_val: num_bigint::BigUint) -> Result<BigInt<N>, Self::Error> {
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
        Self([0u32; N])
    }
}

impl<const N: usize> CanonicalSerialize for BigInt<N> {
    fn serialize_with_mode<W: Write>(
        &self,
        writer: W,
        compress: Compress,
    ) -> Result<(), SerializationError> {
        self.0.serialize_with_mode(writer, compress)
    }

    fn serialized_size(&self, compress: Compress) -> usize {
        self.0.serialized_size(compress)
    }
}

impl<const N: usize> Valid for BigInt<N> {
    fn check(&self) -> Result<(), SerializationError> {
        self.0.check()
    }
}

impl<const N: usize> CanonicalDeserialize for BigInt<N> {
    fn deserialize_with_mode<R: Read>(
        reader: R,
        compress: Compress,
        validate: Validate,
    ) -> Result<Self, SerializationError> {
        Ok(BigInt::<N>(<[u32; N]>::deserialize_with_mode(
            reader, compress, validate,
        )?))
    }
}

impl<const N: usize> Ord for BigInt<N> {
    #[inline]
    fn cmp(&self, other: &Self) -> ::core::cmp::Ordering {
        use core::cmp::Ordering;
        for i in 0..9 {
            let a = &self.0[9 - i - 1];
            let b = &other.0[9 - i - 1];
            if a < b {
                return Ordering::Less;
            } else if a > b {
                return Ordering::Greater;
            }
        }
        Ordering::Equal
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
    fn bitand(self, _other: &BigInt<N>) -> BigInt<N> {
        todo!()
    }
}

impl<const N: usize> BitAnd<&BigInt<N>> for BigInt<N> {
    type Output = BigInt<N>;

    #[inline]
    fn bitand(self, _other: &BigInt<N>) -> BigInt<N> {
        todo!()
    }
}

impl<const N: usize> BitAnd<BigInt<N>> for &BigInt<N> {
    type Output = BigInt<N>;

    #[inline]
    fn bitand(self, _other: BigInt<N>) -> BigInt<N> {
        todo!()
    }
}

impl<const N: usize> BitAnd<BigInt<N>> for BigInt<N> {
    type Output = BigInt<N>;

    #[inline]
    fn bitand(self, _other: BigInt<N>) -> BigInt<N> {
        todo!()
    }
}

impl<const N: usize> BitAndAssign<BigInt<N>> for BigInt<N> {
    fn bitand_assign(&mut self, _other: BigInt<N>) {
        todo!()
    }
}

impl<const N: usize> BitAndAssign<&BigInt<N>> for BigInt<N> {
    fn bitand_assign(&mut self, _other: &BigInt<N>) {
        todo!()
    }
}

impl<const N: usize> BitOr<BigInt<N>> for &BigInt<N> {
    type Output = BigInt<N>;

    #[inline]
    fn bitor(self, _other: BigInt<N>) -> BigInt<N> {
        todo!()
    }
}

impl<const N: usize> BitOr<&BigInt<N>> for &BigInt<N> {
    type Output = BigInt<N>;

    #[inline]
    fn bitor(self, _other: &BigInt<N>) -> BigInt<N> {
        todo!()
    }
}

impl<const N: usize> BitOr<&BigInt<N>> for BigInt<N> {
    type Output = BigInt<N>;

    #[inline]
    fn bitor(self, _other: &BigInt<N>) -> BigInt<N> {
        todo!()
    }
}

impl<const N: usize> BitOr<BigInt<N>> for BigInt<N> {
    type Output = BigInt<N>;

    #[inline]
    fn bitor(self, _other: BigInt<N>) -> BigInt<N> {
        todo!()
    }
}

impl<const N: usize> BitOrAssign<BigInt<N>> for BigInt<N> {
    fn bitor_assign(&mut self, _other: BigInt<N>) {
        todo!()
    }
}

impl<const N: usize> BitOrAssign<&BigInt<N>> for BigInt<N> {
    fn bitor_assign(&mut self, _other: &BigInt<N>) {
        todo!()
    }
}

impl<const N: usize> Shl<u32> for BigInt<N> {
    type Output = BigInt<N>;

    #[inline]
    fn shl(self, _rhs: u32) -> BigInt<N> {
        todo!()
    }
}
impl<const N: usize> Shl<u32> for &BigInt<N> {
    type Output = BigInt<N>;

    #[inline]
    fn shl(self, _rhs: u32) -> BigInt<N> {
        todo!()
    }
}
impl<const N: usize> ShlAssign<u32> for BigInt<N> {
    #[inline]
    fn shl_assign(&mut self, _rhs: u32) {
        todo!()
    }
}

impl<const N: usize> Shr<u32> for BigInt<N> {
    type Output = BigInt<N>;

    #[inline]
    fn shr(self, _rhs: u32) -> BigInt<N> {
        todo!()
    }
}
impl<const N: usize> Shr<u32> for &BigInt<N> {
    type Output = BigInt<N>;

    #[inline]
    fn shr(self, _rhs: u32) -> BigInt<N> {
        todo!()
    }
}
impl<const N: usize> ShrAssign<u32> for BigInt<N> {
    #[inline]
    fn shr_assign(&mut self, _rhs: u32) {
        todo!()
    }
}

impl<const N: usize> BitXor<&BigInt<N>> for BigInt<N> {
    type Output = BigInt<N>;

    #[inline]
    fn bitxor(mut self, other: &BigInt<N>) -> BigInt<N> {
        self ^= other;
        self
    }
}

impl<const N: usize> BitXor<BigInt<N>> for BigInt<N> {
    type Output = BigInt<N>;

    #[inline]
    fn bitxor(self, _other: BigInt<N>) -> BigInt<N> {
        todo!()
    }
}

impl<const N: usize> BitXorAssign<BigInt<N>> for BigInt<N> {
    fn bitxor_assign(&mut self, _other: BigInt<N>) {
        todo!()
    }
}

impl<const N: usize> BitXorAssign<&BigInt<N>> for BigInt<N> {
    fn bitxor_assign(&mut self, _other: &BigInt<N>) {
        todo!()
    }
}

impl<const N: usize> FromStr for BigInt<N> {
    type Err = ParseBigIntError;

    #[inline]
    fn from_str(_s: &str) -> Result<BigInt<N>, ParseBigIntError> {
        todo!()
    }
}

impl<const N: usize> BigInteger for BigInt<N> {
    const NUM_LIMBS: usize = N;

    #[inline]
    fn add_with_carry(&mut self, _other: &Self) -> bool {
        {
            todo!();
            //use arithmetic::adc_for_add_with_carry as adc;

            //let a = &mut self.0;
            //let b = &other.0;
            //let mut carry = 0;

            //if N >= 1 {
            //    carry = adc(&mut a[0], b[0], carry);
            //}
            //if N >= 2 {
            //    carry = adc(&mut a[1], b[1], carry);
            //}
            //if N >= 3 {
            //    carry = adc(&mut a[2], b[2], carry);
            //}
            //if N >= 4 {
            //    carry = adc(&mut a[3], b[3], carry);
            //}
            //if N >= 5 {
            //    carry = adc(&mut a[4], b[4], carry);
            //}
            //if N >= 6 {
            //    carry = adc(&mut a[5], b[5], carry);
            //}
            //for i in 6..N {
            //    carry = adc(&mut a[i], b[i], carry);
            //}
            //carry != 0
        }
    }

    #[inline]
    fn sub_with_borrow(&mut self, _other: &Self) -> bool {
        todo!()
        //use arithmetic::sbb_for_sub_with_borrow as sbb;

        //let a = &mut self.0;
        //let b = &other.0;
        //let mut borrow = 0u8;

        //if N >= 1 {
        //    borrow = sbb(&mut a[0], b[0], borrow);
        //}
        //if N >= 2 {
        //    borrow = sbb(&mut a[1], b[1], borrow);
        //}
        //if N >= 3 {
        //    borrow = sbb(&mut a[2], b[2], borrow);
        //}
        //if N >= 4 {
        //    borrow = sbb(&mut a[3], b[3], borrow);
        //}
        //if N >= 5 {
        //    borrow = sbb(&mut a[4], b[4], borrow);
        //}
        //if N >= 6 {
        //    borrow = sbb(&mut a[5], b[5], borrow);
        //}
        //for i in 6..N {
        //    borrow = sbb(&mut a[i], b[i], borrow);
        //}
        //borrow != 0
    }

    #[inline]
    #[allow(unused)]
    fn mul2(&mut self) -> bool {
        todo!()
        //        #[cfg(all(target_arch = "x86_64", feature = "asm"))]
        //        #[allow(unsafe_code)]
        //        {
        //            let mut carry = 0;
        //
        //            for i in 0..N {
        //                unsafe {
        //                    use core::arch::x86_64::_addcarry_u64;
        //                    carry = _addcarry_u64(carry, self.0[i], self.0[i], &mut self.0[i])
        //                };
        //            }
        //
        //            carry != 0
        //        }
        //
        //        #[cfg(not(all(target_arch = "x86_64", feature = "asm")))]
        //        {
        //            todo!()
        //            //let mut last = 0;
        //            //for i in 0..N {
        //            //    let a = &mut self.0[i];
        //            //    let tmp = *a >> 63;
        //            //    *a <<= 1;
        //            //    *a |= last;
        //            //    last = tmp;
        //            //}
        //            //last != 0
        //}
    }

    #[inline]
    fn mul(&self, _other: &Self) -> (Self, Self) {
        todo!()
    }

    #[inline]
    fn mul_low(&self, _other: &Self) -> Self {
        todo!()
    }

    #[inline]
    fn mul_high(&self, _other: &Self) -> Self {
        todo!()
    }

    #[inline]
    fn muln(&mut self, mut n: u32) {
        if n >= (64 * N) as u32 {
            *self = Self::from(0u64);
            return;
        }

        while n >= 64 {
            let mut t = 0;
            for i in 0..N {
                core::mem::swap(&mut t, &mut self.0[i]);
            }
            n -= 64;
        }

        if n > 0 {
            let mut t = 0;
            #[allow(unused)]
            for i in 0..N {
                let a = &mut self.0[i];
                let t2 = *a >> (64 - n);
                *a <<= n;
                *a |= t;
                t = t2;
            }
        }
    }

    #[inline]
    fn div2(&mut self) {
        todo!()
        //let mut t = 0;
        //for i in 0..N {
        //    let a = &mut self.0[N - i - 1];
        //    let t2 = *a << 63;
        //    *a >>= 1;
        //    *a |= t;
        //    t = t2;
        //}
    }

    #[inline]
    fn divn(&mut self, mut n: u32) {
        if n >= (64 * N) as u32 {
            *self = Self::from(0u64);
            return;
        }

        while n >= 64 {
            let mut t = 0;
            for i in 0..N {
                core::mem::swap(&mut t, &mut self.0[N - i - 1]);
            }
            n -= 64;
        }

        if n > 0 {
            let mut t = 0;
            #[allow(unused)]
            for i in 0..N {
                let a = &mut self.0[N - i - 1];
                let t2 = *a << (64 - n);
                *a >>= n;
                *a |= t;
                t = t2;
            }
        }
    }

    #[inline]
    fn is_odd(&self) -> bool {
        self.0[0] & 1 == 1
    }

    #[inline]
    fn is_even(&self) -> bool {
        !self.is_odd()
    }

    #[inline]
    fn is_zero(&self) -> bool {
        self.0.iter().all(|&e| e == 0)
    }

    #[inline]
    fn num_bits(&self) -> u32 {
        let mut ret = N as u32 * 64;
        for i in self.0.iter().rev() {
            let leading = i.leading_zeros();
            ret -= leading;
            if leading != 64 {
                break;
            }
        }

        ret
    }

    #[inline]
    fn get_bit(&self, i: usize) -> bool {
        if i >= 64 * N {
            false
        } else {
            let limb = i / 64;
            let bit = i - (64 * limb);
            (self.0[limb] & (1 << bit)) != 0
        }
    }

    #[inline]
    fn from_bits_be(_bits: &[bool]) -> Self {
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

    fn from_bits_le(_bits: &[bool]) -> Self {
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
        let mut le_bytes = self.to_bytes_le();
        le_bytes.reverse();
        le_bytes
    }

    #[inline]
    fn to_bytes_le(&self) -> Vec<u8> {
        let array_map = self.0.iter().map(|limb| limb.to_le_bytes());
        let mut res = Vec::with_capacity(N * 8);
        for limb in array_map {
            res.extend_from_slice(&limb);
        }
        res
    }
}
