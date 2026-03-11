use ark_ff::Field;
pub mod fp;
pub use self::fp::*;

pub mod fq;
pub use self::fq::*;

pub mod fft;

#[derive(Debug, PartialEq, Eq)]
pub enum LegendreSymbol {
    Zero = 0,
    QuadraticResidue = 1,
    QuadraticNonResidue = -1,
}

impl LegendreSymbol {
    #[must_use]
    pub fn is_zero(&self) -> bool {
        *self == Self::Zero
    }

    #[must_use]
    pub fn is_qnr(&self) -> bool {
        *self == Self::QuadraticNonResidue
    }

    #[must_use]
    pub fn is_qr(&self) -> bool {
        *self == Self::QuadraticResidue
    }
}

/// The interface for a field that supports an efficient square-root operation.
pub trait SquareRootField: Field {
    /// Returns a `LegendreSymbol`, which indicates whether this field element is
    ///  1 : a quadratic residue
    ///  0 : equal to 0
    /// -1 : a quadratic non-residue
    fn legendre(&self) -> LegendreSymbol;

    /// Returns the square root of self, if it exists.
    #[must_use]
    fn sqrt(&self) -> Option<Self>;

    /// Sets `self` to be the square root of `self`, if it exists.
    fn sqrt_in_place(&mut self) -> Option<&mut Self>;
}
