//! This is used to define common types and associated prologues

use ark_ec::AffineCurve;

/// Alias to refer to the scalar field of a curve.
pub type ScalarField<G> = <G as AffineCurve>::ScalarField;

/// Alias to refer to the base field of a curve.
pub type BaseField<G> = <G as AffineCurve>::BaseField;

/// Fields prologue
pub mod fields {
    pub use super::{BaseField, ScalarField};
}
