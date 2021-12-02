//! Mina signature structure and associated helpers

use std::fmt;

use crate::{BaseField, FieldHelpers, ScalarField};

/// Signature structure
#[derive(Clone, Copy, Eq, fmt::Debug, PartialEq)]
pub struct Signature {
    /// Field component
    pub rx: BaseField,

    /// Scalar component
    pub s: ScalarField,
}

impl Signature {
    /// Create a new signature
    pub fn new(rx: BaseField, s: ScalarField) -> Self {
        Self { rx, s }
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
