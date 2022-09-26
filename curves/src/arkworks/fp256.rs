//! This module introduces a macro that helps you implement the `Field` trait,
//! and other useful traits that field types usually implement in arkworks,
//! for a wrapper trait.

/// Use `impl_field(wrapper, arkf, params)` with:
/// - `wrapper` being the name of the wrapper type
/// - `arkf` being the name of the arkworks field type (a type that implements `ark_ff::Fp256<SomeParams>`)
/// - `params` being the name of the arkworks field parameters type (a type that implements `ark_ff::Fp256Parameters`)
macro_rules! impl_field {
    ($Wrapper: ident, $ArkF: ty, $Params: ty) => {
        paste! {
            //
            // Conversions
            //

            impl From<$ArkF> for $Wrapper {
                #[inline]
                fn from(ark_fp: $ArkF) -> Self {
                    Self(ark_fp)
                }
            }

            impl From<&$ArkF> for $Wrapper {
                #[inline]
                fn from(ark_fp: &$ArkF) -> Self {
                    Self(*ark_fp)
                }
            }

            impl From<$Wrapper> for $ArkF {
                #[inline]
                fn from(fp: $Wrapper) -> Self {
                    fp.0
                }
            }

            impl From<&$Wrapper> for $ArkF {
                #[inline]
                fn from(fp: &$Wrapper) -> Self {
                    fp.0
                }
            }

            //
            //
            //

            impl Default for $Wrapper {
                #[inline]
                fn default() -> Self {
                    ark_ff::Fp256::default().into()
                }
            }
            impl Hash for $Wrapper {
                #[inline]
                fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
                    self.0.hash(state);
                }
            }
            impl Clone for $Wrapper {
                #[inline]
                fn clone(&self) -> Self {
                    self.0.clone().into()
                }
            }
            impl Copy for $Wrapper {}
            impl Debug for $Wrapper {
                #[inline]
                fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
                    f.debug_tuple("Fp256").field(&self.0).finish()
                }
            }
            impl PartialEq for $Wrapper {
                #[inline]
                fn eq(&self, other: &Self) -> bool {
                    self.0.eq(&other.0)
                }
            }
            impl Eq for $Wrapper {}

            //
            //
            //

            impl $Wrapper {
                #[inline]
                pub fn new(x: ark_ff::BigInteger256) -> Self {
                    ark_ff::Fp256::new(x).into()
                }

                pub const fn const_from_str(limbs: &[u64], is_positive: bool, r2: ark_ff::BigInteger256, modulus: ark_ff::BigInteger256, inv: u64) -> Self {
                    Self(ark_ff::Fp256::const_from_str(limbs, is_positive, r2, modulus, inv))
                }
            }

            impl ark_ff::Zero for $Wrapper {
                #[inline]
                fn zero() -> Self {
                    ark_ff::Fp256::zero().into()
                }

                #[inline]
                fn is_zero(&self) -> bool {
                    self.0.is_zero()
                }
            }

            impl ark_ff::One for $Wrapper {
                #[inline]
                fn one() -> Self {
                    ark_ff::Fp256::one().into()
                }

                #[inline]
                fn is_one(&self) -> bool {
                    self.0.is_one()
                }
            }

            impl ark_ff::Field for $Wrapper {
                type BasePrimeField = Self;

                #[inline]
                fn extension_degree() -> u64 {
                    $ArkF::extension_degree()
                }

                #[inline]
                fn from_base_prime_field_elems(elems: &[Self::BasePrimeField]) -> Option<Self> {
                    // TODO: this looks suboptimal
                    let elems: Vec<<$ArkF as ark_ff::Field>::BasePrimeField> =
                        elems.iter().map(|x| x.0).collect();
                    ark_ff::Fp256::from_base_prime_field_elems(&elems).map(Into::into)
                }

                #[inline]
                fn double(&self) -> Self {
                    self.0.double().into()
                }

                #[inline]
                fn double_in_place(&mut self) -> &mut Self {
                    self.0.double_in_place();
                    self
                }

                #[inline]
                fn characteristic() -> &'static [u64] {
                    $ArkF::characteristic()
                }

                #[inline]
                fn from_random_bytes_with_flags<F>(bytes: &[u8]) -> Option<(Self, F)>
                where
                    F: ark_serialize::Flags,
                {
                    ark_ff::Fp256::from_random_bytes_with_flags(bytes).map(|(x, f)| (x.into(), f))
                }

                #[inline]
                fn square(&self) -> Self {
                    self.0.square().into()
                }

                #[inline]
                fn square_in_place(&mut self) -> &mut Self {
                    self.0.square_in_place();
                    self
                }

                #[inline]
                fn inverse(&self) -> Option<Self> {
                    self.0.inverse().map(Into::into)
                }

                #[inline]
                fn inverse_in_place(&mut self) -> Option<&mut Self> {
                    if self.0.inverse_in_place().is_some() {
                        Some(self)
                    } else {
                        None
                    }
                }

                /// The Frobenius map has no effect in a prime field.
                #[inline]
                fn frobenius_map(&mut self, x: usize) {
                    self.0.frobenius_map(x)
                }
            }

            impl ark_ff::PrimeField for $Wrapper {
                type Params = $Params;
                type BigInt = ark_ff::BigInteger256;

                #[inline]
                fn from_repr(r: Self::BigInt) -> Option<Self> {
                    ark_ff::Fp256::from_repr(r).map(Into::into)
                }

                #[inline]
                fn into_repr(&self) -> Self::BigInt {
                    self.0.into_repr()
                }
            }

            impl ark_ff::FftField for $Wrapper {
                type FftParams = $Params;

                #[inline]
                fn two_adic_root_of_unity() -> Self {
                    ark_ff::Fp256::two_adic_root_of_unity().into()
                }

                #[inline]
                fn large_subgroup_root_of_unity() -> Option<Self> {
                    ark_ff::Fp256::large_subgroup_root_of_unity().map(Into::into)
                }

                #[inline]
                fn multiplicative_generator() -> Self {
                    ark_ff::Fp256::multiplicative_generator().into()
                }
            }

            impl ark_ff::SquareRootField for $Wrapper {
                #[inline]
                fn legendre(&self) -> ark_ff::LegendreSymbol {
                    self.0.legendre()
                }

                #[inline]
                fn sqrt(&self) -> Option<Self> {
                    self.0.sqrt().map(Into::into)
                }

                #[inline]
                fn sqrt_in_place(&mut self) -> Option<&mut Self> {
                    if self.0.sqrt_in_place().is_some() {
                        Some(self)
                    } else {
                        None
                    }
                }
            }

            impl Ord for $Wrapper {
                #[inline(always)]
                fn cmp(&self, other: &Self) -> Ordering {
                    self.0.cmp(&other.0)
                }
            }

            impl PartialOrd for $Wrapper {
                #[inline(always)]
                fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
                    self.0.partial_cmp(&other.0)
                }
            }

            impl From<u128> for $Wrapper {
                #[inline]
                fn from(other: u128) -> Self {
                    ark_ff::Fp256::from(other).into()
                }
            }

            impl From<i128> for $Wrapper {
                #[inline]
                fn from(other: i128) -> Self {
                    ark_ff::Fp256::from(other).into()
                }
            }

            impl From<bool> for $Wrapper {
                #[inline]
                fn from(other: bool) -> Self {
                    ark_ff::Fp256::from(other).into()
                }
            }

            impl From<u64> for $Wrapper {
                #[inline]
                fn from(other: u64) -> Self {
                    ark_ff::Fp256::from(other).into()
                }
            }

            impl From<i64> for $Wrapper {
                #[inline]
                fn from(other: i64) -> Self {
                    ark_ff::Fp256::from(other).into()
                }
            }

            impl From<u32> for $Wrapper {
                #[inline]
                fn from(other: u32) -> Self {
                    ark_ff::Fp256::from(other).into()
                }
            }

            impl From<i32> for $Wrapper {
                #[inline]
                fn from(other: i32) -> Self {
                    ark_ff::Fp256::from(other).into()
                }
            }

            impl From<u16> for $Wrapper {
                #[inline]
                fn from(other: u16) -> Self {
                    ark_ff::Fp256::from(other).into()
                }
            }

            impl From<i16> for $Wrapper {
                #[inline]
                fn from(other: i16) -> Self {
                    ark_ff::Fp256::from(other).into()
                }
            }

            impl From<u8> for $Wrapper {
                #[inline]
                fn from(other: u8) -> Self {
                    ark_ff::Fp256::from(other).into()
                }
            }

            impl From<i8> for $Wrapper {
                #[inline]
                fn from(other: i8) -> Self {
                    ark_ff::Fp256::from(other).into()
                }
            }

            impl ark_ff::ToBytes for $Wrapper {
                #[inline]
                fn write<W: Write>(&self, writer: W) -> IoResult<()> {
                    self.0.write(writer)
                }
            }

            impl ark_ff::FromBytes for $Wrapper {
                #[inline]
                fn read<R: Read>(reader: R) -> IoResult<Self> {
                    ark_ff::Fp256::read(reader).map(Into::into)
                }
            }

            impl FromStr for $Wrapper {
                type Err = ();

                #[inline]
                fn from_str(s: &str) -> Result<Self, Self::Err> {
                    ark_ff::Fp256::from_str(s).map(Into::into)
                }
            }

            impl Display for $Wrapper {
                #[inline]
                fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
                    Display::fmt(&self.0, f)
                }
            }

            impl Neg for $Wrapper {
                type Output = Self;

                #[inline]
                #[must_use]
                fn neg(self) -> Self {
                    self.0.neg().into()
                }
            }

            impl<'a> Add<&'a $Wrapper> for $Wrapper {
                type Output = Self;

                #[inline]
                fn add(self, other: &Self) -> Self {
                    self.0.add(&other.0).into()
                }
            }

            impl<'a> Sub<&'a $Wrapper> for $Wrapper {
                type Output = Self;

                #[inline]
                fn sub(self, other: &Self) -> Self {
                    self.0.sub(&other.0).into()
                }
            }

            impl<'a> Mul<&'a $Wrapper> for $Wrapper {
                type Output = Self;

                #[inline]
                fn mul(self, other: &Self) -> Self {
                    self.0.mul(&other.0).into()
                }
            }

            impl<'a> Div<&'a $Wrapper> for $Wrapper {
                type Output = Self;

                /// Returns `self * other.inverse()` if `other.inverse()` is `Some`, and
                /// panics otherwise.
                #[inline]
                fn div(self, other: &Self) -> Self {
                    self.0.div(&other.0).into()
                }
            }

            impl<'a> AddAssign<&'a Self> for $Wrapper {
                #[inline]
                fn add_assign(&mut self, other: &Self) {
                    self.0.add_assign(&other.0);
                }
            }

            impl<'a> SubAssign<&'a Self> for $Wrapper {
                #[inline]
                fn sub_assign(&mut self, other: &Self) {
                    self.0.sub_assign(&other.0);
                }
            }

            impl<'a> MulAssign<&'a Self> for $Wrapper {
                #[inline]
                fn mul_assign(&mut self, other: &Self) {
                    self.0.mul_assign(&other.0);
                }
            }

            impl<'a> DivAssign<&'a Self> for $Wrapper {
                #[inline]
                fn div_assign(&mut self, other: &Self) {
                    self.0.div_assign(&other.0);
                }
            }

            #[allow(unused_qualifications)]
            impl core::ops::Add<Self> for $Wrapper {
                type Output = Self;

                #[inline]
                fn add(self, other: Self) -> Self {
                    self.0.add(other.0).into()
                }
            }

            #[allow(unused_qualifications)]
            impl<'a> core::ops::Add<&'a mut Self> for $Wrapper {
                type Output = Self;

                #[inline]
                fn add(self, other: &'a mut Self) -> Self {
                    self.0.add(other.0).into()
                }
            }

            #[allow(unused_qualifications)]
            impl core::ops::Sub<Self> for $Wrapper {
                type Output = Self;

                #[inline]
                fn sub(self, other: Self) -> Self {
                    self.0.sub(other.0).into()
                }
            }

            #[allow(unused_qualifications)]
            impl<'a> core::ops::Sub<&'a mut Self> for $Wrapper {
                type Output = Self;

                #[inline]
                fn sub(self, other: &'a mut Self) -> Self {
                    self.0.sub(other.0).into()
                }
            }

            #[allow(unused_qualifications)]
            impl core::iter::Sum<Self> for $Wrapper {
                #[inline]
                fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
                    $ArkF::sum(iter.map(|x| x.0)).into()
                }
            }

            #[allow(unused_qualifications)]
            impl<'a> core::iter::Sum<&'a Self> for $Wrapper {
                #[inline]
                fn sum<I: Iterator<Item = &'a Self>>(iter: I) -> Self {
                    $ArkF::sum(iter.map(|x| x.0)).into()
                }
            }

            #[allow(unused_qualifications)]
            impl core::ops::AddAssign<Self> for $Wrapper {
                #[inline]
                fn add_assign(&mut self, other: Self) {
                    self.0.add_assign(&other.0)
                }
            }

            #[allow(unused_qualifications)]
            impl core::ops::SubAssign<Self> for $Wrapper {
                #[inline]
                fn sub_assign(&mut self, other: Self) {
                    self.0.sub_assign(&other.0)
                }
            }

            #[allow(unused_qualifications)]
            impl<'a> core::ops::AddAssign<&'a mut Self> for $Wrapper {
                #[inline]
                fn add_assign(&mut self, other: &'a mut Self) {
                    self.0.add_assign(&other.0)
                }
            }

            #[allow(unused_qualifications)]
            impl<'a> core::ops::SubAssign<&'a mut Self> for $Wrapper {
                #[inline]
                fn sub_assign(&mut self, other: &'a mut Self) {
                    self.0.sub_assign(&other.0)
                }
            }

            #[allow(unused_qualifications)]
            impl core::ops::Mul<Self> for $Wrapper {
                type Output = Self;

                #[inline]
                fn mul(self, other: Self) -> Self {
                    self.0.mul(other.0).into()
                }
            }

            #[allow(unused_qualifications)]
            impl core::ops::Div<Self> for $Wrapper {
                type Output = Self;

                #[inline]
                fn div(self, other: Self) -> Self {
                    self.0.div(other.0).into()
                }
            }

            #[allow(unused_qualifications)]
            impl<'a> core::ops::Mul<&'a mut Self> for $Wrapper {
                type Output = Self;

                #[inline]
                fn mul(self, other: &'a mut Self) -> Self {
                    self.0.mul(other.0).into()
                }
            }

            #[allow(unused_qualifications)]
            impl<'a> core::ops::Div<&'a mut Self> for $Wrapper {
                type Output = Self;

                #[inline]
                fn div(self, other: &'a mut Self) -> Self {
                    self.0.div(other.0).into()
                }
            }

            #[allow(unused_qualifications)]
            impl core::iter::Product<Self> for $Wrapper {
                #[inline]
                fn product<I: Iterator<Item = Self>>(iter: I) -> Self {
                    ark_ff::Fp256::product(iter.map(|x| x.0)).into()
                }
            }

            #[allow(unused_qualifications)]
            impl<'a> core::iter::Product<&'a Self> for $Wrapper {
                #[inline]
                fn product<I: Iterator<Item = &'a Self>>(iter: I) -> Self {
                    ark_ff::Fp256::product(iter.map(|x| x.0)).into()
                }
            }

            #[allow(unused_qualifications)]
            impl core::ops::MulAssign<Self> for $Wrapper {
                #[inline]
                fn mul_assign(&mut self, other: Self) {
                    self.0.mul_assign(&other.0)
                }
            }

            #[allow(unused_qualifications)]
            impl<'a> core::ops::DivAssign<&'a mut Self> for $Wrapper {
                #[inline]
                fn div_assign(&mut self, other: &'a mut Self) {
                    self.0.div_assign(&other.0)
                }
            }

            #[allow(unused_qualifications)]
            impl<'a> core::ops::MulAssign<&'a mut Self> for $Wrapper {
                #[inline]
                fn mul_assign(&mut self, other: &'a mut Self) {
                    self.0.mul_assign(&other.0)
                }
            }

            #[allow(unused_qualifications)]
            impl core::ops::DivAssign<Self> for $Wrapper {
                #[inline]
                fn div_assign(&mut self, other: Self) {
                    self.0.div_assign(&other.0)
                }
            }

            impl zeroize::Zeroize for $Wrapper {
                // The phantom data does not contain element-specific data
                // and thus does not need to be zeroized.
                #[inline]
                fn zeroize(&mut self) {
                    self.0.zeroize();
                }
            }

            impl Into<ark_ff::BigInteger256> for $Wrapper {
                #[inline]
                fn into(self) -> ark_ff::BigInteger256 {
                    self.0.into()
                }
            }

            impl From<ark_ff::BigInteger256> for $Wrapper {
                /// Converts `Self::BigInteger` into `Self`
                ///
                /// # Panics
                /// This method panics if `int` is larger than `P::MODULUS`.
                #[inline]
                fn from(int: ark_ff::BigInteger256) -> Self {
                    ark_ff::Fp256::from(int).into()
                }
            }

            impl From<num_bigint::BigUint> for $Wrapper {
                #[inline]
                fn from(val: num_bigint::BigUint) -> Self {
                    ark_ff::Fp256::from(val).into()
                }
            }

            impl Into<num_bigint::BigUint> for $Wrapper {
                #[inline]
                fn into(self) -> num_bigint::BigUint {
                    self.0.into()
                }
            }

            impl ark_serialize::CanonicalSerializeWithFlags for $Wrapper {
                #[inline]
                fn serialize_with_flags<W: std::io::Write, F: ark_serialize::Flags>(
                    &self,
                    writer: W,
                    flags: F,
                ) -> Result<(), ark_serialize::SerializationError> {
                    self.0.serialize_with_flags(writer, flags)
                }

                #[inline]
                fn serialized_size_with_flags<F: ark_serialize::Flags>(&self) -> usize {
                    self.0.serialized_size_with_flags::<F>()
                }
            }

            impl ark_serialize::CanonicalSerialize for $Wrapper {
                #[inline]
                fn serialize<W: std::io::Write>(
                    &self,
                    writer: W,
                ) -> Result<(), ark_serialize::SerializationError> {
                    self.0.serialize(writer)
                }

                #[inline]
                fn serialized_size(&self) -> usize {
                    self.0.serialized_size()
                }
            }

            impl ark_serialize::CanonicalDeserializeWithFlags for $Wrapper {
                #[inline]
                fn deserialize_with_flags<R: std::io::Read, F: ark_serialize::Flags>(
                    reader: R,
                ) -> Result<(Self, F), ark_serialize::SerializationError> {
                    ark_ff::Fp256::deserialize_with_flags::<R, F>(reader).map(|(x, f)| (x.into(), f))
                }
            }

            impl ark_serialize::CanonicalDeserialize for $Wrapper {
                #[inline]
                fn deserialize<R: std::io::Read>(reader: R) -> Result<Self, ark_serialize::SerializationError> {
                    ark_ff::Fp256::deserialize(reader).map(Into::into)
                }
            }

            impl ark_std::rand::distributions::Distribution<$Wrapper>
                for ark_std::rand::distributions::Standard
            {
                #[inline]
                fn sample<R: ark_std::rand::Rng + ?Sized>(&self, rng: &mut R) -> $Wrapper {
                    let ark_fp: $ArkF = self.sample(rng);
                    $Wrapper(ark_fp)
                }
            }

        }
    }
}

// Rust note: this is how we can use this macro within the crate.
pub(crate) use impl_field;
