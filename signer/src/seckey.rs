//! Secret key structures and helpers

use crate::ScalarField;
use ark_ff::UniformRand;
use rand::{self, CryptoRng, RngCore};

/// Secret key
#[derive(Clone, PartialEq, Eq)] // No Debug nor Display
pub struct SecKey(ScalarField);

impl SecKey {
    /// Generate a random secret key
    pub fn rand(rng: &mut (impl RngCore + CryptoRng)) -> Self {
        let secret: ScalarField = ScalarField::rand(rng);

        Self(secret)
    }

    /// Create a secret key from scalar field element
    #[must_use]
    #[allow(clippy::needless_pass_by_value)]
    pub fn new(scalar: ScalarField) -> Self {
        Self(scalar)
    }

    /// Borrows secret key as scalar field element
    #[must_use]
    pub fn scalar(&self) -> &ScalarField {
        &self.0
    }

    /// Convert secret key into scalar field element
    #[must_use]
    pub fn into_scalar(self) -> ScalarField {
        self.0
    }
}
