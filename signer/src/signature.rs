//! Mina signature structure and associated helpers

use crate::{BaseField, ScalarField};
use ark_ff::One;
use core::fmt;
use o1_utils::FieldHelpers;

/// Signature structure
#[derive(Clone, Eq, fmt::Debug, PartialEq)]
pub struct Signature {
    /// Base field component
    pub rx: BaseField,

    /// Scalar field component
    pub s: ScalarField,
}

impl Signature {
    /// Create a new signature
    pub fn new(rx: BaseField, s: ScalarField) -> Self {
        Self { rx, s }
    }

    /// Create a dummy signature, whose components are both equal to one.
    /// Use it with caution.
    pub fn dummy() -> Self {
        Self {
            rx: BaseField::one(),
            s: ScalarField::one(),
        }
    }
}

impl fmt::Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut rx_bytes = self.rx.to_bytes();
        let mut s_bytes = self.s.to_bytes();
        rx_bytes.reverse();
        s_bytes.reverse();

        write!(f, "{}{}", hex::encode(rx_bytes), hex::encode(s_bytes))
    }
}
