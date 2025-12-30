//! Currency types for Mina Protocol transactions.
//!
//! This module provides numeric types for representing amounts and fees
//! in Mina Protocol transactions. All types are `no_std` compatible.

use core::{
    fmt,
    ops::{Add, Neg, Sub},
};

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
    pub fn is_pos(&self) -> bool {
        matches!(self, Sgn::Pos)
    }

    /// Returns `true` if the sign is negative.
    #[inline]
    pub fn is_neg(&self) -> bool {
        matches!(self, Sgn::Neg)
    }

    /// Negates the sign, returning the opposite.
    #[inline]
    pub fn negate(&self) -> Self {
        match self {
            Sgn::Pos => Sgn::Neg,
            Sgn::Neg => Sgn::Pos,
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
            Sgn::Pos => write!(f, "+"),
            Sgn::Neg => write!(f, "-"),
        }
    }
}

/// Trait for types that have minimum and maximum bounds.
pub trait MinMax {
    /// Returns the minimum value of this type.
    fn min() -> Self;
    /// Returns the maximum value of this type.
    fn max() -> Self;
}

/// Trait for unsigned numeric types supporting arithmetic operations.
///
/// This trait defines the core operations needed for currency magnitude types
/// like [`Amount`] and [`Fee`]. It provides both checked and wrapping arithmetic,
/// as well as comparison and zero-checking operations.
pub trait Magnitude:
    Copy + Clone + PartialOrd + Ord + PartialEq + Eq + Default + fmt::Debug + MinMax
{
    /// The number of bits used to represent this type.
    const NBITS: usize;

    /// Returns the zero value for this type.
    fn zero() -> Self;

    /// Returns `true` if this value is zero.
    fn is_zero(&self) -> bool;

    /// Returns the absolute difference between `self` and `other`.
    fn abs_diff(&self, other: &Self) -> Self;

    /// Wrapping (modular) addition.
    fn wrapping_add(&self, other: &Self) -> Self;

    /// Wrapping (modular) subtraction.
    fn wrapping_sub(&self, other: &Self) -> Self;

    /// Checked addition. Returns `None` if overflow occurred.
    fn checked_add(&self, other: &Self) -> Option<Self>;

    /// Checked subtraction. Returns `None` if underflow occurred.
    fn checked_sub(&self, other: &Self) -> Option<Self>;

    /// Checked multiplication. Returns `None` if overflow occurred.
    fn checked_mul(&self, other: &Self) -> Option<Self>;

    /// Checked division. Returns `None` if `other` is zero.
    fn checked_div(&self, other: &Self) -> Option<Self>;

    /// Checked remainder. Returns `None` if `other` is zero.
    fn checked_rem(&self, other: &Self) -> Option<Self>;

    /// Returns the inner value as a `u64`.
    fn as_u64(&self) -> u64;

    /// Creates a value from a `u64`. Returns `None` if out of range.
    fn from_u64(value: u64) -> Option<Self>;

    /// Addition with overflow flag. Returns `(result, overflow_occurred)`.
    fn add_flagged(&self, other: &Self) -> (Self, bool) {
        match self.checked_add(other) {
            Some(result) => (result, false),
            None => (self.wrapping_add(other), true),
        }
    }

    /// Subtraction with underflow flag. Returns `(result, underflow_occurred)`.
    fn sub_flagged(&self, other: &Self) -> (Self, bool) {
        match self.checked_sub(other) {
            Some(result) => (result, false),
            None => (self.wrapping_sub(other), true),
        }
    }
}

/// A signed value composed of a magnitude and a sign.
///
/// This type represents signed quantities where the sign is tracked
/// separately from the magnitude. This is useful for representing
/// values that can be positive or negative without using two's complement.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct Signed<T: Magnitude> {
    /// The absolute value (magnitude) of the signed quantity.
    pub magnitude: T,
    /// The sign of the value.
    pub sgn: Sgn,
}

impl<T: Magnitude> Default for Signed<T> {
    fn default() -> Self {
        Self::zero()
    }
}

impl<T: Magnitude> Signed<T> {
    /// Creates a new signed value with the given magnitude and sign.
    pub fn new(magnitude: T, sgn: Sgn) -> Self {
        Self { magnitude, sgn }
    }

    /// Creates a new positive signed value.
    pub fn pos(magnitude: T) -> Self {
        Self {
            magnitude,
            sgn: Sgn::Pos,
        }
    }

    /// Creates a new negative signed value.
    pub fn neg(magnitude: T) -> Self {
        Self {
            magnitude,
            sgn: Sgn::Neg,
        }
    }

    /// Creates the zero value.
    pub fn zero() -> Self {
        Self {
            magnitude: T::zero(),
            sgn: Sgn::Pos,
        }
    }

    /// Returns `true` if this value is zero.
    pub fn is_zero(&self) -> bool {
        self.magnitude.is_zero()
    }

    /// Returns `true` if this value is positive (including zero).
    pub fn is_pos(&self) -> bool {
        self.sgn.is_pos()
    }

    /// Returns `true` if this value is negative.
    pub fn is_neg(&self) -> bool {
        self.sgn.is_neg() && !self.magnitude.is_zero()
    }

    /// Negates this signed value.
    pub fn negate(&self) -> Self {
        Self {
            magnitude: self.magnitude,
            sgn: self.sgn.negate(),
        }
    }

    /// Checked addition of two signed values.
    ///
    /// Returns `None` if overflow occurs.
    pub fn checked_add(&self, other: &Self) -> Option<Self> {
        if self.sgn == other.sgn {
            // Same sign: add magnitudes, keep sign
            let magnitude = self.magnitude.checked_add(&other.magnitude)?;
            Some(Self {
                magnitude,
                sgn: self.sgn,
            })
        } else {
            // Opposite signs: subtract smaller from larger
            let (magnitude, sgn) = if self.magnitude >= other.magnitude {
                (self.magnitude.abs_diff(&other.magnitude), self.sgn)
            } else {
                (other.magnitude.abs_diff(&self.magnitude), other.sgn)
            };
            Some(Self { magnitude, sgn })
        }
    }

    /// Checked subtraction of two signed values.
    ///
    /// Returns `None` if overflow occurs.
    pub fn checked_sub(&self, other: &Self) -> Option<Self> {
        self.checked_add(&other.negate())
    }
}

impl<T: Magnitude + fmt::Display> fmt::Display for Signed<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.sgn.is_neg() && !self.magnitude.is_zero() {
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

impl<T: Magnitude> Add for Signed<T> {
    type Output = Option<Self>;

    fn add(self, other: Self) -> Self::Output {
        self.checked_add(&other)
    }
}

impl<T: Magnitude> Sub for Signed<T> {
    type Output = Option<Self>;

    fn sub(self, other: Self) -> Self::Output {
        self.checked_sub(&other)
    }
}

/// Macro to implement common numeric type functionality.
///
/// This generates a newtype wrapper around `u64` with the [`Magnitude`]
/// and [`MinMax`] traits implemented, along with common arithmetic operations.
macro_rules! impl_number {
    ($name:ident, $doc:expr) => {
        #[doc = $doc]
        #[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(u64);

        impl $name {
            /// Creates a new value from a `u64`.
            pub const fn new(value: u64) -> Self {
                Self(value)
            }

            /// Returns the inner `u64` value.
            pub const fn inner(&self) -> u64 {
                self.0
            }
        }

        impl MinMax for $name {
            fn min() -> Self {
                Self(0)
            }

            fn max() -> Self {
                Self(u64::MAX)
            }
        }

        impl Magnitude for $name {
            const NBITS: usize = 64;

            fn zero() -> Self {
                Self(0)
            }

            fn is_zero(&self) -> bool {
                self.0 == 0
            }

            fn abs_diff(&self, other: &Self) -> Self {
                Self(self.0.abs_diff(other.0))
            }

            fn wrapping_add(&self, other: &Self) -> Self {
                Self(self.0.wrapping_add(other.0))
            }

            fn wrapping_sub(&self, other: &Self) -> Self {
                Self(self.0.wrapping_sub(other.0))
            }

            fn checked_add(&self, other: &Self) -> Option<Self> {
                self.0.checked_add(other.0).map(Self)
            }

            fn checked_sub(&self, other: &Self) -> Option<Self> {
                self.0.checked_sub(other.0).map(Self)
            }

            fn checked_mul(&self, other: &Self) -> Option<Self> {
                self.0.checked_mul(other.0).map(Self)
            }

            fn checked_div(&self, other: &Self) -> Option<Self> {
                self.0.checked_div(other.0).map(Self)
            }

            fn checked_rem(&self, other: &Self) -> Option<Self> {
                self.0.checked_rem(other.0).map(Self)
            }

            fn as_u64(&self) -> u64 {
                self.0
            }

            fn from_u64(value: u64) -> Option<Self> {
                Some(Self(value))
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

        impl Add for $name {
            type Output = Option<Self>;

            fn add(self, other: Self) -> Self::Output {
                self.checked_add(&other)
            }
        }

        impl Sub for $name {
            type Output = Option<Self>;

            fn sub(self, other: Self) -> Self::Output {
                self.checked_sub(&other)
            }
        }
    };
}

impl_number!(Amount, "An amount of currency in nanomina (1 MINA = 1e9 nanomina).\n\nThis type represents positive currency amounts used in transactions,\naccount balances, and coinbase rewards.");

impl_number!(Fee, "A transaction fee in nanomina (1 MINA = 1e9 nanomina).\n\nThis type represents fees paid for transaction processing.");

#[cfg(test)]
mod tests {
    extern crate alloc;
    use alloc::format;

    use super::*;

    #[test]
    fn test_sgn_operations() {
        assert!(Sgn::Pos.is_pos());
        assert!(!Sgn::Pos.is_neg());
        assert!(Sgn::Neg.is_neg());
        assert!(!Sgn::Neg.is_pos());
        assert_eq!(Sgn::Pos.negate(), Sgn::Neg);
        assert_eq!(Sgn::Neg.negate(), Sgn::Pos);
        assert_eq!(-Sgn::Pos, Sgn::Neg);
    }

    #[test]
    fn test_amount_basic() {
        let a = Amount::new(100);
        let b = Amount::new(50);

        assert_eq!(a.inner(), 100);
        assert_eq!(b.inner(), 50);
        assert!(!a.is_zero());
        assert!(Amount::zero().is_zero());
    }

    #[test]
    fn test_amount_arithmetic() {
        let a = Amount::new(100);
        let b = Amount::new(50);

        assert_eq!(a.checked_add(&b), Some(Amount::new(150)));
        assert_eq!(a.checked_sub(&b), Some(Amount::new(50)));
        assert_eq!(b.checked_sub(&a), None); // underflow
        assert_eq!(a.abs_diff(&b), Amount::new(50));
    }

    #[test]
    fn test_signed_operations() {
        let pos = Signed::<Amount>::pos(Amount::new(100));
        let neg = Signed::<Amount>::neg(Amount::new(50));

        assert!(pos.is_pos());
        assert!(neg.is_neg());
        assert!(!Signed::<Amount>::zero().is_neg());

        // +100 + (-50) = +50
        let result = pos.checked_add(&neg).unwrap();
        assert_eq!(result.magnitude, Amount::new(50));
        assert!(result.is_pos());

        // +100 + (+100) = +200
        let result = pos.checked_add(&pos).unwrap();
        assert_eq!(result.magnitude, Amount::new(200));
        assert!(result.is_pos());

        // -50 + (-50) = -100
        let result = neg.checked_add(&neg).unwrap();
        assert_eq!(result.magnitude, Amount::new(100));
        assert!(result.is_neg());
    }

    #[test]
    fn test_fee_basic() {
        let fee = Fee::new(1_000_000_000); // 1 MINA
        assert_eq!(fee.inner(), 1_000_000_000);
        assert_eq!(fee.as_u64(), 1_000_000_000);
    }

    #[test]
    fn test_magnitude_traits() {
        assert_eq!(<Amount as MinMax>::min(), Amount::new(0));
        assert_eq!(<Amount as MinMax>::max(), Amount::new(u64::MAX));
        assert_eq!(<Fee as MinMax>::min(), Fee::new(0));
        assert_eq!(<Fee as MinMax>::max(), Fee::new(u64::MAX));
    }

    #[test]
    fn test_display() {
        assert_eq!(format!("{}", Sgn::Pos), "+");
        assert_eq!(format!("{}", Sgn::Neg), "-");
        assert_eq!(format!("{}", Amount::new(100)), "100");
        assert_eq!(
            format!("{}", Signed::<Amount>::pos(Amount::new(100))),
            "100"
        );
        assert_eq!(
            format!("{}", Signed::<Amount>::neg(Amount::new(100))),
            "-100"
        );
    }
}
