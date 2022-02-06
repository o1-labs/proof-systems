//! Signer domain and helpers
//!
//! Shorthands and helpers for base and scalar field elements

use ark_ec::AffineCurve;
use mina_curves::pasta::pallas;

/// Affine curve point type
pub use pallas::Affine as CurvePoint;
/// Base field element type
pub type BaseField = <CurvePoint as AffineCurve>::BaseField;
/// Scalar field element type
pub type ScalarField = <CurvePoint as AffineCurve>::ScalarField;
