//! Currency types for Mina Protocol transactions.
//!
//! This module provides numeric types for representing amounts and fees
//! in Mina Protocol transactions. All types are `no_std` compatible.

use core::{fmt, ops::Neg};

/// Sign of a value, either positive or negative.
///
/// Used in conjunction with [`Signed`] to represent signed quantities
/// where the sign is tracked separately from the magnitude.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Hash)]
pub enum Sgn {
    /// Positive value
    #[default]
    Pos,
    /// Negative value
    Neg,
}

impl Sgn {
    /// Returns `true` if the sign is positive.
    #[inline]
    #[must_use]
    pub const fn is_pos(&self) -> bool {
        matches!(self, Self::Pos)
    }

    /// Returns `true` if the sign is negative.
    #[inline]
    #[must_use]
    pub const fn is_neg(&self) -> bool {
        matches!(self, Self::Neg)
    }

    /// Negates the sign, returning the opposite.
    #[inline]
    #[must_use]
    pub const fn negate(&self) -> Self {
        match self {
            Self::Pos => Self::Neg,
            Self::Neg => Self::Pos,
        }
    }
}

impl Neg for Sgn {
    type Output = Self;

    fn neg(self) -> Self::Output {
        self.negate()
    }
}

impl fmt::Display for Sgn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pos => write!(f, "+"),
            Self::Neg => write!(f, "-"),
        }
    }
}

/// Trait for unsigned numeric types supporting arithmetic operations.
///
/// This trait defines the core operations needed for currency magnitude types
/// like [`Amount`] and [`Fee`].
pub trait Magnitude:
    Copy + Clone + PartialOrd + Ord + PartialEq + Eq + Default + fmt::Debug
{
    /// The zero value for this type.
    const ZERO: Self;

    /// Returns `true` if this value is zero.
    fn is_zero(self) -> bool;

    /// Returns the absolute difference between `self` and `other`.
    #[must_use]
    fn abs_diff(self, other: Self) -> Self;

    /// Checked addition. Returns `None` if overflow occurred.
    fn checked_add(self, other: Self) -> Option<Self>;

    /// Checked subtraction. Returns `None` if underflow occurred.
    fn checked_sub(self, other: Self) -> Option<Self>;
}

/// A signed value composed of a magnitude and a sign.
///
/// This type represents signed quantities where the sign is tracked
/// separately from the magnitude. This is useful for representing
/// values that can be positive or negative without using two's complement.
///
/// Zero is always normalized to have a positive sign.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct Signed<T: Magnitude> {
    magnitude: T,
    sgn: Sgn,
}

impl<T: Magnitude> Default for Signed<T> {
    fn default() -> Self {
        Self::zero()
    }
}

impl<T: Magnitude> Signed<T> {
    /// Normalizes the sign: zero magnitude always has positive sign.
    fn normalize(magnitude: T, sgn: Sgn) -> Self {
        let sgn = if magnitude.is_zero() { Sgn::Pos } else { sgn };
        Self { magnitude, sgn }
    }

    /// Creates a new signed value with the given magnitude and sign.
    ///
    /// Zero magnitude is always normalized to positive sign.
    #[must_use]
    pub fn new(magnitude: T, sgn: Sgn) -> Self {
        Self::normalize(magnitude, sgn)
    }

    /// Creates a new positive signed value.
    ///
    /// Zero magnitude is normalized to positive sign.
    #[must_use]
    pub fn pos(magnitude: T) -> Self {
        Self::normalize(magnitude, Sgn::Pos)
    }

    /// Creates a new negative signed value.
    ///
    /// Zero magnitude is normalized to positive sign.
    #[must_use]
    pub fn neg(magnitude: T) -> Self {
        Self::normalize(magnitude, Sgn::Neg)
    }

    /// Creates the zero value.
    #[must_use]
    pub const fn zero() -> Self {
        Self {
            magnitude: T::ZERO,
            sgn: Sgn::Pos,
        }
    }

    /// Returns the magnitude (absolute value).
    #[must_use]
    pub const fn magnitude(&self) -> T {
        self.magnitude
    }

    /// Returns the sign.
    #[must_use]
    pub const fn sgn(&self) -> Sgn {
        self.sgn
    }

    /// Returns `true` if this value is zero.
    #[must_use]
    pub fn is_zero(&self) -> bool {
        self.magnitude.is_zero()
    }

    /// Returns `true` if this value is positive (including zero).
    #[must_use]
    pub const fn is_pos(&self) -> bool {
        self.sgn.is_pos()
    }

    /// Returns `true` if this value is negative.
    #[must_use]
    pub const fn is_neg(&self) -> bool {
        self.sgn.is_neg()
    }

    /// Negates this signed value.
    #[must_use]
    pub fn negate(&self) -> Self {
        Self::normalize(self.magnitude, self.sgn.negate())
    }

    /// Checked addition of two signed values.
    ///
    /// Returns `None` if overflow occurs.
    #[must_use]
    pub fn checked_add(&self, other: &Self) -> Option<Self> {
        if self.sgn == other.sgn {
            // Same sign: add magnitudes, keep sign
            let magnitude = self.magnitude.checked_add(other.magnitude)?;
            Some(Self::normalize(magnitude, self.sgn))
        } else {
            // Opposite signs: subtract smaller from larger
            let (magnitude, sgn) = if self.magnitude >= other.magnitude {
                (self.magnitude.abs_diff(other.magnitude), self.sgn)
            } else {
                (other.magnitude.abs_diff(self.magnitude), other.sgn)
            };
            Some(Self::normalize(magnitude, sgn))
        }
    }

    /// Checked subtraction of two signed values.
    ///
    /// Returns `None` if overflow occurs.
    #[must_use]
    pub fn checked_sub(&self, other: &Self) -> Option<Self> {
        self.checked_add(&other.negate())
    }
}

impl<T: Magnitude + fmt::Display> fmt::Display for Signed<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.sgn.is_neg() {
            write!(f, "-{}", self.magnitude)
        } else {
            write!(f, "{}", self.magnitude)
        }
    }
}

impl<T: Magnitude> Neg for Signed<T> {
    type Output = Self;

    fn neg(self) -> Self::Output {
        self.negate()
    }
}

/// Macro to implement common numeric type functionality.
///
/// This generates a newtype wrapper around `u64` with the [`Magnitude`]
/// trait implemented.
macro_rules! impl_number {
    ($name:ident, $doc:expr) => {
        #[doc = $doc]
        #[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(u64);

        impl $name {
            /// The minimum value (zero).
            pub const MIN: Self = Self(0);

            /// The maximum value.
            pub const MAX: Self = Self(u64::MAX);

            /// Creates a new value from a `u64`.
            #[must_use]
            pub const fn new(value: u64) -> Self {
                Self(value)
            }

            /// Returns the inner `u64` value.
            #[must_use]
            pub const fn inner(&self) -> u64 {
                self.0
            }
        }

        impl Magnitude for $name {
            const ZERO: Self = Self(0);

            fn is_zero(self) -> bool {
                self.0 == 0
            }

            fn abs_diff(self, other: Self) -> Self {
                Self(self.0.abs_diff(other.0))
            }

            fn checked_add(self, other: Self) -> Option<Self> {
                self.0.checked_add(other.0).map(Self)
            }

            fn checked_sub(self, other: Self) -> Option<Self> {
                self.0.checked_sub(other.0).map(Self)
            }
        }

        impl From<u64> for $name {
            fn from(value: u64) -> Self {
                Self(value)
            }
        }

        impl From<$name> for u64 {
            fn from(value: $name) -> u64 {
                value.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.0)
            }
        }
    };
}

impl_number!(
    Amount,
    "An amount of currency in nanomina (1 MINA = 1e9 nanomina).\n\n\
     This type represents positive currency amounts used in transactions,\n\
     account balances, and coinbase rewards."
);

impl_number!(
    Fee,
    "A transaction fee in nanomina (1 MINA = 1e9 nanomina).\n\n\
     This type represents fees paid for transaction processing."
);

impl From<Fee> for Amount {
    fn from(fee: Fee) -> Self {
        Self::new(fee.inner())
    }
}
