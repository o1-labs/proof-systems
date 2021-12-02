//! Secret key structures and helpers

use crate::ScalarField;

/// Secret key
#[derive(Clone, Copy, PartialEq, Eq)] // No Debug nor Display
pub struct SecKey(ScalarField);

impl SecKey {
    /// Create a secret key from scalar field element
    pub fn new(scalar: ScalarField) -> Self {
        Self(scalar)
    }

    /// Convert secret key into scalar field element
    pub fn to_scalar(self) -> ScalarField {
        self.0
    }
}
