use crate::{
    biginteger::{
        BigInteger as _BigInteger, webnode::BigInteger256,
    },
    bytes::{FromBytes, ToBytes},
    fields::{FftField, Field, LegendreSymbol, PrimeField, SquareRootField},
};
use ark_serialize::*;
use ark_std::{
    cmp::{Ord, Ordering, PartialOrd},
    fmt::{Display, Formatter, Result as FmtResult},
    io::{Read, Result as IoResult, Write},
    marker::PhantomData,
    ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Sub, SubAssign},
    str::FromStr, One, Zero,
};

impl<C: Fp256Parameters> Into<BigInteger256> for Fp256<C> {
    fn into(self) -> BigInteger256 {
        self.into_repr()
    }
}
impl<C: Fp256Parameters> core::convert::TryFrom<BigInteger256> for Fp256<C> {
    type Error = crate::fields::arithmetic::InvalidBigInt;

    /// Converts `Self::BigInteger` into `Self`
    ///
    /// This method returns an error if `int` is larger than `P::MODULUS`.
    fn try_from(int: BigInteger256) -> Result<Self, Self::Error> {
        Self::from_repr(int).ok_or(crate::fields::arithmetic::InvalidBigInt)
    }
}

const SHIFT: u32 = 29;
const MASK: u32 = (1 << SHIFT) - 1;

const SHIFT64: u64 = SHIFT as u64;
const MASK64: u64 = MASK as u64;

pub const fn from_64x4(pa: [u64; 4]) -> [u32; 9] {
    let mut p = [0u32; 9];
    p[0] = (pa[0] & MASK64) as u32;
    p[1] = ((pa[0] >> 29) & MASK64) as u32;
    p[2] = (((pa[0] >> 58) | (pa[1] << 6)) & MASK64) as u32;
    p[3] = ((pa[1] >> 23) & MASK64) as u32;
    p[4] = (((pa[1] >> 52) | (pa[2] << 12)) & MASK64) as u32;
    p[5] = ((pa[2] >> 17) & MASK64) as u32;
    p[6] = (((pa[2] >> 46) | (pa[3] << 18)) & MASK64) as u32;
    p[7] = ((pa[3] >> 11) & MASK64) as u32;
    p[8] = (pa[3] >> 40) as u32;
    p
}
pub const fn to_64x4(pa: [u32; 9]) -> [u64; 4] {
    let mut p = [0u64; 4];
    p[0] = pa[0] as u64;
    p[0] |= (pa[1] as u64) << 29;
    p[0] |= (pa[2] as u64) << 58;
    p[1] = (pa[2] as u64) >> 6;
    p[1] |= (pa[3] as u64) << 23;
    p[1] |= (pa[4] as u64) << 52;
    p[2] = (pa[4] as u64) >> 12;
    p[2] |= (pa[5] as u64) << 17;
    p[2] |= (pa[6] as u64) << 46;
    p[3] = (pa[6] as u64) >> 18;
    p[3] |= (pa[7] as u64) << 11;
    p[3] |= (pa[8] as u64) << 40;
    p
}

const fn gte_modulus<C: Fp256Parameters>(x: &BigInteger256) -> bool {
    let mut i = Fp256::<C>::NLIMBS - 1;
    loop {
        // don't fix warning -- that makes it 15% slower!
        #[allow(clippy::comparison_chain)]
        if x.0[i] > C::MODULUS.0[i] {
            return true;
        } else if x.0[i] < C::MODULUS.0[i] {
            return false;
        }
        if i == 0 {
            break;
        }
        i -= 1;
    }
    true
}

#[ark_ff_asm::unroll_for_loops]
#[inline(always)]
const fn conditional_reduce<C: Fp256Parameters>(x: &mut BigInteger256) {
    if gte_modulus::<C>(&x) {
        for i in 0..9 {
            x.0[i] = x.0[i].wrapping_sub(C::MODULUS.0[i]);
        }
        for i in 1..9 {
            x.0[i] += ((x.0[i - 1] as i32) >> SHIFT) as u32;
        }
        for i in 0..8 {
            x.0[i] &= MASK;
        }
    }
}

#[ark_ff_asm::unroll_for_loops]
#[inline(always)]
fn add_assign<C: Fp256Parameters>(x: &mut BigInteger256, y: &BigInteger256) {
    let y = &y.0;
    let mut tmp: u32;
    let mut carry: i32 = 0;

    for i in 0..9 {
        tmp = x.0[i] + y[i] + (carry as u32);
        carry = (tmp as i32) >> SHIFT;
        x.0[i] = tmp & MASK;
    }

    if gte_modulus::<C>(x) {
        carry = 0;
        for i in 0..9 {
            tmp = x.0[i].wrapping_sub(C::MODULUS.0[i]) + (carry as u32);
            carry = (tmp as i32) >> SHIFT;
            x.0[i] = tmp & MASK;
        }
    }
}

#[derive(Clone, Copy, Default, Eq, PartialEq, Hash)]
pub struct Fp256<C: Fp256Parameters> (pub BigInteger256, PhantomData<C>);

/// Note that this implementation of `Ord` compares field elements viewing
/// them as integers in the range 0, 1, ..., P::MODULUS - 1. However, other
/// implementations of `PrimeField` might choose a different ordering, and
/// as such, users should use this `Ord` for applications where
/// any ordering suffices (like in a BTreeMap), and not in applications
/// where a particular ordering is required.
impl<P: Fp256Parameters> Ord for Fp256<P> {
    #[inline(always)]
    fn cmp(&self, other: &Self) -> Ordering {
        self.into_repr().cmp(&other.into_repr())
    }
}
/// Note that this implementation of `PartialOrd` compares field elements viewing
/// them as integers in the range 0, 1, ..., `P::MODULUS` - 1. However, other
/// implementations of `PrimeField` might choose a different ordering, and
/// as such, users should use this `PartialOrd` for applications where
/// any ordering suffices (like in a BTreeMap), and not in applications
/// where a particular ordering is required.
impl<P: Fp256Parameters> PartialOrd for Fp256<P> {
    #[inline(always)]
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<C: Fp256Parameters> Display for Fp256<C> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.write_fmt(format_args!("{:?}", self.0))
    }
}

impl<C: Fp256Parameters> ark_std::fmt::Debug for Fp256<C> {
    fn fmt(&self, f: &mut ark_std::fmt::Formatter<'_>) -> ark_std::fmt::Result {
        use crate::ark_std::string::ToString;
        let r: BigInteger256 = self.into_repr();
        let bigint: num_bigint::BigUint = r.into();
        let s = bigint.to_string();

        let name = match C::T.0[0] {
            0x192d30ed => "Fp",
            0xc46eb21 => "Fq",
            _ => panic!(),
        };

        f.write_fmt(format_args!("{}({})", name, s))
    }
}

impl<C: Fp256Parameters> Fp256<C> {
    const NLIMBS: usize = 9;

    #[inline]
    pub const fn new(element: BigInteger256) -> Self {
        Self(element, PhantomData)
    }
    const fn const_is_zero(&self) -> bool {
        let mut index = 0;
        let mut is_zero = true;
        while index < Self::NLIMBS {
            is_zero &= self.0.0[index] == 0;
            index += 1;
        }
        is_zero
    }
    const fn const_neg(self, modulus: BigInteger256) -> Self {
        if !self.const_is_zero() {
            Self::new(Self::sub_noborrow(&modulus, &self.0))
        } else {
            self
        }
    }

    #[ark_ff_asm::unroll_for_loops]
    #[allow(unused_assignments)]
    const fn sub_noborrow(a: &BigInteger256, b: &BigInteger256) -> BigInteger256 {
        /// Calculate a - b - borrow, returning the result and modifying
        /// the borrow value.
        macro_rules! sbb {
            ($a:expr, $b:expr, &mut $borrow:expr$(,)?) => {{
                let tmp = (1u64 << 32) + ($a as u64) - ($b as u64) - ($borrow as u64);
                $borrow = if tmp >> 32 == 0 { 1 } else { 0 };
                tmp as u32
            }};
        }
        let mut a = *a;
        let mut borrow = 0;
        for i in 0..9 {
            a.0[i] = sbb!(a.0[i], b.0[i], &mut borrow);
        }
        a
    }

    /// Interpret a string of decimal numbers as a prime field element.
    /// Does not accept unnecessary leading zeroes or a blank string.
    /// For *internal* use only; please use the `field_new` macro instead
    /// of this method
    #[doc(hidden)]
    pub const fn const_from_str(
        limbs: &[u64],
        is_positive: bool,
        r2: BigInteger256,
        modulus: BigInteger256,
        inv: u64,
    ) -> Self {
        let repr = match limbs {
            [a, b, c, d] => BigInteger256::from_64x4([*a, *b, *c, *d]),
            [a, b, c] => BigInteger256::from_64x4([*a, *b, *c, 0]),
            [a, b] => BigInteger256::from_64x4([*a, *b, 0, 0]),
            [a] => BigInteger256::from_64x4([*a, 0, 0, 0]),
            _ => panic!(),
        };
        let res = Self::const_from_repr(repr, r2, modulus, inv as u32);
        if is_positive {
            res
        } else {
            res.const_neg(modulus)
        }
    }

    #[inline]
    pub(crate) const fn const_from_repr(
        repr: BigInteger256,
        r2: BigInteger256,
        modulus: BigInteger256,
        inv: u32,
    ) -> Self {
        let mut r = Self::new(repr);
        if r.const_is_zero() {
            r
        } else {
            r.const_mul(&Fp256(r2, PhantomData), &modulus, inv);
            r
        }
    }

    const U64_MODULUS: [u64; 9] = {
        let mut modulus64 = [0u64; 9];
        let modulus = C::MODULUS;
        let mut i = 0;
        while i < 9 {
            modulus64[i] = modulus.0[i] as u64;
            i += 1;
        }
        modulus64
    };

    /// Implementation based on https://github.com/o1-labs/proof-systems/pull/2638
    #[ark_ff_asm::unroll_for_loops]
    #[inline(always)]
    const fn const_mul_without_reduce(&mut self, other: &Self, _modulus: &BigInteger256, _inv: u32) {
        let x = &mut self.0.0;
        let y = &other.0.0;

        let mut y_local = [0u64; 9];
        for index in 0..9 {
            y_local[index] = y[index] as u64;
        }

        let mut xy = [0u64; 9];

        for i in 0..9 {
            let xi = x[i] as u64;

            let tmp = (xi * y_local[0]) + xy[0];
            let qi = (MASK64 + 1) - (tmp & MASK64);
            let carry = (tmp + (qi * Self::U64_MODULUS[0])) >> SHIFT64;

            for j in 1..8 {
                let did_carry = j == 1;
                let mut xy_j = xy[j];
                if did_carry {
                    xy_j += carry;
                }
                xy[j - 1] = (xy_j + (xi * y_local[j])) + (qi * Self::U64_MODULUS[j]);
            }

            let j = Self::NLIMBS - 1;
            xy[j - 1] = (xi * y_local[j]) + (qi * Self::U64_MODULUS[j]);
        }

        for j in 1..9 {
            x[j - 1] = (xy[j - 1] as u32) & MASK;
            xy[j] += xy[j - 1] >> SHIFT64;
        }
        x[Self::NLIMBS - 1] = xy[Self::NLIMBS - 1] as u32;
    }

    #[inline(always)]
    const fn const_mul(&mut self, other: &Self, modulus: &BigInteger256, inv: u32) {
        self.const_mul_without_reduce(other, modulus, inv);
        self.const_reduce(modulus);
    }

    #[inline(always)]
    const fn const_reduce(&mut self, _modulus: &BigInteger256) {
        conditional_reduce::<C>(&mut self.0);
    }

    // don't fix warning -- that makes it 15% slower!
    #[allow(clippy::comparison_chain)]
    const fn const_is_valid(&self, _modulus: &BigInteger256) -> bool {
        let mut i = Fp256::<C>::NLIMBS - 1;
        loop {
            if self.0.0[i] > C::MODULUS.0[i] {
                return false;
            } else if self.0.0[i] < C::MODULUS.0[i] {
                return true;
            }
            if i == 0 {
                break;
            }
            i -= 1;
        }
        false
    }

    /// Implementation based on https://github.com/o1-labs/proof-systems/pull/2638
    #[ark_ff_asm::unroll_for_loops]
    #[inline(always)]
    const fn const_square(&mut self) {
        let mut x = [0u64; 9];
        for i in 0..9 {
            x[i] = self.0.0[i] as u64;
        }
        let mut xy = [0u64; 9];
        for i in 0..9 {
            let j = 0;
            let tmp = if i == 0 {
                x[i] * x[j]
            } else {
                ((x[i] * x[j]) << 1) + xy[j]
            };
            let qi = (MASK64 + 1) - (tmp & MASK64);
            let carry = (tmp + (qi * Self::U64_MODULUS[0])) >> SHIFT64;
            for j in 1..8 {
                let did_carry = j == 1;
                let mut xy_j = xy[j];
                if did_carry {
                    xy_j += carry;
                }
                if j <= i {
                    let mut tmp = x[i] * x[j];
                    if j < i {
                       tmp <<= 1;
                    }
                    xy_j += tmp;
                }
                xy[j - 1] = xy_j + (qi * Self::U64_MODULUS[j]);
            }
            let j = 8;
            xy[j - 1] = if i == j {
                (x[i] * x[j]) + (qi * Self::U64_MODULUS[j])
            } else {
                qi * Self::U64_MODULUS[j]
            };
        }
        for j in 1..9 {
            self.0.0[j - 1] = (xy[j - 1] as u32) & MASK;
            xy[j] += xy[j - 1] >> SHIFT64;
        }
        self.0.0[9 - 1] = xy[9 - 1] as u32;

        self.const_reduce(&C::MODULUS);
    }
}

impl<C: Fp256Parameters> Fp256<C> {
    pub(crate) fn is_valid(&self) -> bool {
        self.const_is_valid(&C::MODULUS)
    }
    fn reduce(&mut self) {
        self.const_reduce(&C::MODULUS);
    }
}

impl<C: Fp256Parameters> Zero for Fp256<C> {
    fn zero() -> Self {
        Self(BigInteger256([0; 9]), PhantomData)
    }
    fn is_zero(&self) -> bool {
        self.0.0 == [0u32; 9]
    }
}

impl<C: Fp256Parameters> One for Fp256<C> {
    fn one() -> Self {
        Self(C::R, PhantomData)
    }
    fn is_one(&self) -> bool {
        self.0 == C::R
    }
}

impl<C: Fp256Parameters> Neg for Fp256<C> {
    type Output = Self;
    #[must_use]
    fn neg(self) -> Self {
        if !self.is_zero() {
            let mut tmp = C::MODULUS;
            tmp.sub_noborrow(&self.0);
            Fp256(tmp, PhantomData)
        } else {
            self
        }
    }
}
impl<C: Fp256Parameters> core::ops::DivAssign<Self> for Fp256<C> {
    fn div_assign(&mut self, other: Self) {
        self.div_assign(&other)
    }
}
impl<C: Fp256Parameters> Add<Self> for Fp256<C> {
    type Output = Self;
    #[inline(always)]
    fn add(mut self, other: Self) -> Self {
        self.add_assign(other);
        self
    }
}
impl<C: Fp256Parameters> Sub<Self> for Fp256<C> {
    type Output = Self;
    fn sub(mut self, other: Self) -> Self {
        self.sub_assign(other);
        self
    }
}
impl<C: Fp256Parameters> Div<Self> for Fp256<C> {
    type Output = Self;
    fn div(mut self, other: Self) -> Self {
        self.div_assign(other);
        self
    }
}
impl<C: Fp256Parameters> core::ops::AddAssign<Self> for Fp256<C> {
    #[inline(always)]
    fn add_assign(&mut self, other: Self) {
        add_assign::<C>(&mut self.0, &other.0)
    }
}
impl<C: Fp256Parameters> Mul<Self> for Fp256<C> {
    type Output = Self;
    #[inline(always)]
    fn mul(mut self, other: Self) -> Self {
        self.mul_assign(other);
        self
    }
}
impl<C: Fp256Parameters> core::ops::MulAssign<Self> for Fp256<C> {
    #[inline(always)]
    fn mul_assign(&mut self, other: Self) {
        self.const_mul(&other, &C::MODULUS, C::INV as u32);
    }
}
impl<C: Fp256Parameters> SubAssign<Self> for Fp256<C> {
    fn sub_assign(&mut self, other: Self) {
        if other.0 > self.0 {
            self.0.add_nocarry(&C::MODULUS);
        }
        self.0.sub_noborrow(&other.0);
    }
}
impl<C: Fp256Parameters> core::iter::Sum<Self> for Fp256<C> {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::zero(), core::ops::Add::add)
    }
}
impl<C: Fp256Parameters> core::iter::Product<Self> for Fp256<C> {
    fn product<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::one(), Mul::mul)
    }
}

impl<'a, C: Fp256Parameters> Div<&'a Self> for Fp256<C> {
    type Output = Self;
    fn div(mut self, other: &'a Self) -> Self {
        self.div_assign(other);
        self
    }
}
impl<'a, C: Fp256Parameters> DivAssign<&'a Self> for Fp256<C> {
    fn div_assign(&mut self, other: &'a Self) {
        self.mul_assign(&other.inverse().unwrap());
    }
}
impl<'a, C: Fp256Parameters> SubAssign<&'a Self> for Fp256<C> {
    fn sub_assign(&mut self, other: &'a Self) {
        if other.0 > self.0 {
            self.0.add_nocarry(&C::MODULUS);
        }
        self.0.sub_noborrow(&other.0);
    }
}
impl<'a, C: Fp256Parameters> Sub<&'a Self> for Fp256<C> {
    type Output = Self;
    fn sub(mut self, other: &'a Self) -> Self {
        self.sub_assign(other);
        self
    }
}
impl<'a, C: Fp256Parameters> core::iter::Product<&'a Self> for Fp256<C> {
    fn product<I: Iterator<Item = &'a Self>>(iter: I) -> Self {
        iter.fold(Self::one(), Mul::mul)
    }
}
impl<'a, C: Fp256Parameters> core::iter::Sum<&'a Self> for Fp256<C> {
    fn sum<I: Iterator<Item = &'a Self>>(iter: I) -> Self {
        iter.fold(Self::zero(), core::ops::Add::add)
    }
}
impl<'a, C: Fp256Parameters> Add<&'a Self> for Fp256<C> {
    type Output = Self;
    #[inline(always)]
    fn add(mut self, other: &'a Self) -> Self {
        self.add_assign(other);
        self
    }
}
impl<'a, C: Fp256Parameters> core::ops::AddAssign<&'a Self> for Fp256<C> {
    #[inline(always)]
    fn add_assign(&mut self, other: &'a Self) {
        add_assign::<C>(&mut self.0, &other.0)
    }
}
impl<'a, C: Fp256Parameters> Mul<&'a Self> for Fp256<C> {
    type Output = Self;
    #[inline(always)]
    fn mul(mut self, other: &'a Self) -> Self {
        self.mul_assign(other);
        self
    }
}
impl<'a, C: Fp256Parameters> core::ops::MulAssign<&'a Self> for Fp256<C> {
    #[inline(always)]
    fn mul_assign(&mut self, other: &'a Self) {
        self.const_mul(&other, &C::MODULUS, C::INV as u32)
    }
}

impl<C: Fp256Parameters> From<u128> for Fp256<C> {
    fn from(value: u128) -> Self {
        let hi = (value >> 64) as u64;
        let lo = value as u64;
        Self::from_repr(BigInteger256(from_64x4([lo, hi, 0, 0]))).unwrap()
    }
}
impl<C: Fp256Parameters> From<u64> for Fp256<C> {
    fn from(value: u64) -> Self {
        Self::from_repr(BigInteger256::from_64x4([value, 0, 0, 0])).unwrap()
    }
}
impl<C: Fp256Parameters> From<u32> for Fp256<C> {
    fn from(value: u32) -> Self {
        Self::from_repr(BigInteger256::from_64x4([value as u64, 0, 0, 0])).unwrap()
    }
}
impl<C: Fp256Parameters> From<i64> for Fp256<C> {
    fn from(value: i64) -> Self {
        let abs = Self::from(value.unsigned_abs());
        if value.is_positive() {
            abs
        } else {
            -abs
        }
    }
}
impl<C: Fp256Parameters> From<i32> for Fp256<C> {
    fn from(value: i32) -> Self {
        let abs = Self::from(value.unsigned_abs());
        if value.is_positive() {
            abs
        } else {
            -abs
        }
    }
}
impl<C: Fp256Parameters> From<u16> for Fp256<C> {
    fn from(value: u16) -> Self {
        Self::from_repr(BigInteger256::from_64x4([value as u64, 0, 0, 0])).unwrap()
    }
}
impl<C: Fp256Parameters> From<u8> for Fp256<C> {
    fn from(value: u8) -> Self {
        Self::from_repr(BigInteger256::from_64x4([value as u64, 0, 0, 0])).unwrap()
    }
}
impl<C: Fp256Parameters> From<bool> for Fp256<C> {
    fn from(value: bool) -> Self {
        Self::from_repr(BigInteger256::from_64x4([value as u64, 0, 0, 0])).unwrap()
    }
}

impl<C: Fp256Parameters> CanonicalSerializeWithFlags for Fp256<C> {
    fn serialize_with_flags<W: ark_std::io::Write, F: Flags>(
        &self,
        mut writer: W,
        flags: F,
    ) -> Result<(), SerializationError> {
        if F::BIT_SIZE > 8 {
            return Err(SerializationError::NotEnoughSpace);
        }
        let output_byte_size = buffer_byte_size(C::MODULUS_BITS as usize + F::BIT_SIZE);
        let mut bytes = [0u8; 4 * 8 + 1];
        self.write(&mut bytes[..4 * 8])?;
        bytes[output_byte_size - 1] |= flags.u8_bitmask();
        writer.write_all(&bytes[..output_byte_size])?;
        Ok(())
    }
    fn serialized_size_with_flags<F: Flags>(&self) -> usize {
        todo!()
        // buffer_byte_size(P::MODULUS_BITS as usize + F::BIT_SIZE)
    }
}
impl<C: Fp256Parameters> CanonicalSerialize for Fp256<C> {
    fn serialize<W: ark_std::io::Write>(&self, writer: W) -> Result<(), SerializationError> {
        self.serialize_with_flags(writer, EmptyFlags)
    }
    fn serialized_size(&self) -> usize {
        self.serialized_size_with_flags::<EmptyFlags>()
    }
}
impl<C: Fp256Parameters> CanonicalDeserializeWithFlags for Fp256<C> {
    fn deserialize_with_flags<R: ark_std::io::Read, F: Flags>(
        mut reader: R,
    ) -> Result<(Self, F), SerializationError> {
        if F::BIT_SIZE > 8 {
            return Err(SerializationError::NotEnoughSpace);
        }
        let output_byte_size = buffer_byte_size(C::MODULUS_BITS as usize + F::BIT_SIZE);
        let mut masked_bytes = [0; 4 * 8 + 1];
        reader.read_exact(&mut masked_bytes[..output_byte_size])?;
        let flags = F::from_u8_remove_flags(&mut masked_bytes[output_byte_size - 1])
            .ok_or(SerializationError::UnexpectedFlags)?;
        Ok((Self::read(&masked_bytes[..])?, flags))
    }
}
impl<C: Fp256Parameters> CanonicalDeserialize for Fp256<C> {
    fn deserialize<R: ark_std::io::Read>(reader: R) -> Result<Self, SerializationError> {
        Self::deserialize_with_flags::<R, EmptyFlags>(reader).map(|(r, _)| r)
    }
}

impl<C: Fp256Parameters + 'static + Send + Sync + Sized> PrimeField for Fp256<C> {
    type Params = C;
    type BigInt = BigInteger256;
    #[inline]
    fn from_repr(r: BigInteger256) -> Option<Self> {
        let mut r = Self(r, PhantomData);
        if r.is_zero() {
            Some(r)
        } else if r.is_valid() {
            r *= &Self(C::R2, PhantomData);
            Some(r)
        } else {
            None
        }
    }
    #[inline]
    #[allow(clippy::modulo_one)]
    fn into_repr(&self) -> BigInteger256 {
        let one = BigInteger256([1, 0, 0, 0, 0, 0, 0, 0, 0]);
        self.mul(Self(one, PhantomData)).0
    }
}

impl<C: Fp256Parameters> From<num_bigint::BigUint> for Fp256<C> {
    fn from(val: num_bigint::BigUint) -> Self {
        Self::from_le_bytes_mod_order(&val.to_bytes_le())
    }
}
impl<C: Fp256Parameters> Into<num_bigint::BigUint> for Fp256<C> {
    fn into(self) -> num_bigint::BigUint {
        self.into_repr().into()
    }
}

impl<C: Fp256Parameters> FromStr for Fp256<C> {
    type Err = ();
    /// Interpret a string of numbers as a (congruent) prime field element.
    /// Does not accept unnecessary leading zeroes or a blank string.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() {
            return Err(());
        }
        if s == "0" {
            return Ok(Self::zero());
        }
        let mut res = Self::zero();
        use core::convert::TryFrom;
        let ten = Self::try_from(<Self as PrimeField>::BigInt::from(10)).unwrap();
        let mut first_digit = true;
        for c in s.chars() {
            match c.to_digit(10) {
                Some(c) => {
                    if first_digit {
                        if c == 0 {
                            return Err(());
                        }
                        first_digit = false;
                    }
                    res.mul_assign(&ten);
                    let digit = Self::from(u64::from(c));
                    res.add_assign(&digit);
                },
                None => {
                    return Err(());
                },
            }
        }
        if !res.is_valid() {
            Err(())
        } else {
            Ok(res)
        }
    }
}

impl<C: Fp256Parameters> ToBytes for Fp256<C> {
    fn write<W: Write>(&self, writer: W) -> IoResult<()> {
        self.into_repr().write(writer)
    }
}
impl<C: Fp256Parameters> FromBytes for Fp256<C> {
    fn read<R: Read>(reader: R) -> IoResult<Self> {
        BigInteger256::read(reader).and_then(|b| match Fp256::from_repr(b) {
            Some(f) => Ok(f),
            None => Err(crate::error("FromBytes::read failed")),
        })
    }
}

impl<C: Fp256Parameters> Field for Fp256<C> {
    type BasePrimeField = Self;
    fn extension_degree() -> u64 {
        1
    }
    fn from_base_prime_field_elems(elems: &[Self::BasePrimeField]) -> Option<Self> {
        if elems.len() != (Self::extension_degree() as usize) {
            return None;
        }
        Some(elems[0])
    }
    #[inline]
    fn double(&self) -> Self {
        let mut temp = *self;
        temp.double_in_place();
        temp
    }
    #[inline]
    fn double_in_place(&mut self) -> &mut Self {
        self.0.mul2();
        self.reduce();
        self
    }
    #[inline]
    fn characteristic() -> [u64; 4] {
        C::MODULUS.to_64x4()
    }
    #[inline]
    fn from_random_bytes_with_flags<F: Flags>(bytes: &[u8]) -> Option<(Self, F)> {
        if F::BIT_SIZE > 8 {
            return None;
        } else {
            let mut result_bytes = [0u8; 4 * 8 + 1];
            result_bytes
                .iter_mut()
                .zip(bytes)
                .for_each(|(result, input)| {
                    *result = *input;
                });
            let last_limb_mask = (u64::MAX >> C::REPR_SHAVE_BITS).to_le_bytes();
            let mut last_bytes_mask = [0u8; 9];
            last_bytes_mask[..8].copy_from_slice(&last_limb_mask);
            let output_byte_size = buffer_byte_size(C::MODULUS_BITS as usize + F::BIT_SIZE);
            let flag_location = output_byte_size - 1;
            let flag_location_in_last_limb = flag_location - (8 * (4 - 1));
            let last_bytes = &mut result_bytes[8 * (4 - 1)..];
            let flags_mask = u8::MAX.checked_shl(8 - (F::BIT_SIZE as u32)).unwrap_or(0);
            let mut flags: u8 = 0;
            for (i, (b, m)) in last_bytes.iter_mut().zip(&last_bytes_mask).enumerate() {
                if i == flag_location_in_last_limb {
                    flags = *b & flags_mask;
                }
                *b &= m;
            }
            Self::deserialize(&result_bytes[..(4 * 8)])
                .ok()
                .and_then(|f| F::from_u8(flags).map(|flag| (f, flag)))
        }
    }
    #[inline(always)]
    fn square(&self) -> Self {
        let mut temp = self.clone();
        temp.square_in_place();
        temp
    }
    #[inline(always)]
    fn square_in_place(&mut self) -> &mut Self {
        self.const_square();
        self
    }
    #[inline]
    fn inverse(&self) -> Option<Self> {
        if self.is_zero() {
            None
        } else {
            let one = BigInteger256::from(1);
            let mut u = self.0;
            let mut v = C::MODULUS;
            let mut b = Self(C::R2, PhantomData);
            let mut c = Self::zero();
            while u != one && v != one {
                while u.is_even() {
                    u.div2();
                    if b.0.is_even() {
                        b.0.div2();
                    } else {
                        b.0.add_nocarry(&C::MODULUS);
                        b.0.div2();
                    }
                }
                while v.is_even() {
                    v.div2();
                    if c.0.is_even() {
                        c.0.div2();
                    } else {
                        c.0.add_nocarry(&C::MODULUS);
                        c.0.div2();
                    }
                }
                if v < u {
                    u.sub_noborrow(&v);
                    b.sub_assign(&c);
                } else {
                    v.sub_noborrow(&u);
                    c.sub_assign(&b);
                }
            }
            if u == one {
                Some(b)
            } else {
                Some(c)
            }
        }
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
    fn frobenius_map(&mut self, _: usize) {}
}

#[cfg(not(feature = "32x9"))]
impl<C: Fp256Parameters> ark_std::rand::distributions::Distribution<Fp256<C>>
    for ark_std::rand::distributions::Standard
{
    #[inline]
    fn sample<R: ark_std::rand::Rng + ?Sized>(&self, rng: &mut R) -> Fp256<C> {
        loop {
            if !(C::REPR_SHAVE_BITS <= 64) {
                panic!("assertion failed: P::REPR_SHAVE_BITS <= 64")
            }
            let mask = if C::REPR_SHAVE_BITS == 64 {
                0
            } else {
                core::u64::MAX >> C::REPR_SHAVE_BITS
            };

            let mut tmp: [u64; 4] = rng.sample(ark_std::rand::distributions::Standard);
            tmp.as_mut().last_mut().map(|val| *val &= mask);

            let tmp = Fp256(BigInteger256::from_64x4(tmp), PhantomData);
            if tmp.is_valid() {
                return tmp;
            }
        }
    }
}

// During tests, we want to generate the same fields than on native (to test witness generation etc)
#[cfg(feature = "32x9")]
impl<C: Fp256Parameters> ark_std::rand::distributions::Distribution<Fp256<C>>
    for ark_std::rand::distributions::Standard
{
    #[inline]
    fn sample<R: ark_std::rand::Rng + ?Sized>(&self, rng: &mut R) -> Fp256<C> {
        loop {
            if !(C::REPR_SHAVE_BITS <= 64) {
                panic!("assertion failed: P::REPR_SHAVE_BITS <= 64")
            }
            let mask = if C::REPR_SHAVE_BITS == 64 {
                0
            } else {
                core::u64::MAX >> C::REPR_SHAVE_BITS
            };
            let mut tmp: [u64; 4] = rng.sample(ark_std::rand::distributions::Standard);
            tmp.as_mut().last_mut().map(|val| *val &= mask);
            let is_fp = match C::T.0[0] {
                0x192d30ed => true,
                0xc46eb21 => false,
                _ => panic!(),
            };
            const FP_MODULUS: [u64; 4] = [
                0x992d30ed00000001,
                0x224698fc094cf91b,
                0x0,
                0x4000000000000000,
            ];
            const FQ_MODULUS: [u64; 4] = [
                0x8c46eb2100000001,
                0x224698fc0994a8dd,
                0x0,
                0x4000000000000000,
            ];
            let (modulus, inv) = if is_fp {
                (FP_MODULUS, 11037532056220336127)
            } else {
                (FQ_MODULUS, 10108024940646105087)
            };
            let is_valid = || {
                for (random, modulus) in tmp.iter().copied().zip(modulus).rev() {
                    if random > modulus {
                        return false;
                    } else if random < modulus {
                        return true;
                    }
                }
                false
            };
            if !is_valid() {
                continue;
            }
            let mut r = tmp;
            // Montgomery Reduction
            for i in 0..4 {
                let k = r[i].wrapping_mul(inv);
                let mut carry = 0;
                mac_with_carry!(r[i], k, modulus[0] as _, &mut carry);
                for j in 1..4 {
                    r[(j + i) % 4] = mac_with_carry!(r[(j + i) % 4], k, modulus[j], &mut carry);
                }
                r[i % 4] = carry;
            }
            tmp = r;
            return Fp256::<C>::from_repr(BigInteger256::from_64x4(tmp)).unwrap();
        }
    }
}

pub struct NewFpParameters;

impl<C: Fp256Parameters> zeroize::DefaultIsZeroes for Fp256<C> {}

impl<C: Fp256Parameters> FftField for Fp256<C> {
    type FftParams = C;
    fn two_adic_root_of_unity() -> Self {
        Fp256::<C>(C::TWO_ADIC_ROOT_OF_UNITY, PhantomData)
    }
    fn large_subgroup_root_of_unity() -> Option<Self> {
        Some(Fp256::<C>(C::LARGE_SUBGROUP_ROOT_OF_UNITY?, PhantomData))
    }
    fn multiplicative_generator() -> Self {
        Fp256::<C>(C::GENERATOR, PhantomData)
    }
}

impl<C: Fp256Parameters> SquareRootField for Fp256<C> {
    #[inline]
    fn legendre(&self) -> LegendreSymbol {
        use crate::fields::LegendreSymbol::*;

        let modulus_minus_one_div_two = C::MODULUS_MINUS_ONE_DIV_TWO.to_64x4();
        let s = self.pow(modulus_minus_one_div_two);
        if s.is_zero() {
            Zero
        } else if s.is_one() {
            QuadraticResidue
        } else {
            QuadraticNonResidue
        }
    }
    #[inline]
    fn sqrt(&self) -> Option<Self> {
        {
            let t_minus_one_div_two = C::T_MINUS_ONE_DIV_TWO.to_64x4();

            if self.is_zero() {
                return Some(Self::zero());
            }
            let mut z = Self::qnr_to_t();
            let mut w = self.pow(t_minus_one_div_two);
            let mut x = w * self;
            let mut b = x * &w;
            let mut v = C::TWO_ADICITY as usize;
            while !b.is_one() {
                let mut k = 0usize;
                let mut b2k = b;
                while !b2k.is_one() {
                    b2k.square_in_place();
                    k += 1;
                }
                if k == (C::TWO_ADICITY as usize) {
                    return None;
                }
                let j = v - k;
                w = z;
                for _ in 1..j {
                    w.square_in_place();
                }
                z = w.square();
                b *= &z;
                x *= &w;
                v = k;
            }
            if x.square() == *self {
                return Some(x);
            } else {
                #[cfg(debug_assertions)]
                {
                    use crate::fields::LegendreSymbol::*;
                    if self.legendre() != QuadraticNonResidue {
                        panic!(
                            "Input has a square root per its legendre symbol, but it was not found",
                        )
                    }
                }
                None
            }
        }
    }
    fn sqrt_in_place(&mut self) -> Option<&mut Self> {
        (*self).sqrt().map(|sqrt| {
            *self = sqrt;
            self
        })
    }
}

pub trait Fp256Parameters:
    crate::FpParameters<BigInt = BigInteger256>
    + ark_std::fmt::Debug
    + Clone
    + Copy
    + Default
    + Eq
    + PartialEq
    + PartialOrd
    + Ord
    + core::hash::Hash
    + 'static
    + Send
    + Sync
    + Sized
{
}
