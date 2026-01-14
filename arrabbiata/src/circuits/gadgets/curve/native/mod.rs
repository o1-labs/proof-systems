//! Native field elliptic curve operations.
//!
//! This module provides circuit gadgets for elliptic curve operations
//! where the curve's base field matches the circuit's native field.
//!
//! ## Curve Form
//!
//! All operations use the short Weierstrass form: y² = x³ + ax + b
//!
//! The gadgets are parameterized by a curve type `C` that must implement
//! [`ark_ec::short_weierstrass::SWCurveConfig`], ensuring at compile time
//! that the curve is in short Weierstrass form.
//!
//! This enables type-safe circuit composition: when combining gadgets
//! (e.g., Schnorr signature using scalar multiplication), the curve types
//! are checked at compile time, preventing mismatched curves.
//!
//! ## Legacy Parameters
//!
//! [`WeierstrassParams`] is provided for backwards compatibility.
//! Prefer using the curve-typed gadgets when possible.
//!
//! ## Available Gadgets
//!
//! - [`CurveNativeAddGadget`] - Addition of two points
//! - [`CurveNativeDoubleGadget`] - Specialized point doubling
//! - [`CurveNativeScalarMulStepGadget`] - One step of double-and-add scalar multiplication
//! - [`CurveNativeScalarMulGadget`] - Full scalar multiplication

mod ec_add;
mod ec_double;
mod ec_scale;

pub use ec_add::CurveNativeAddGadget;
pub use ec_double::CurveNativeDoubleGadget;
pub use ec_scale::{CurveNativeScalarMulGadget, CurveNativeScalarMulStepGadget};

use ark_ec::short_weierstrass::SWCurveConfig;
use core::marker::PhantomData;

/// Type-safe curve parameters for short Weierstrass curves in affine coordinates.
///
/// This provides compile-time guarantees that:
/// 1. The curve is in short Weierstrass form (y² = x³ + ax + b)
/// 2. Points are in affine coordinates (x, y) rather than projective
/// 3. The curve type is checked during circuit composition
///
/// Using the curve type parameter `C` ensures type-safe circuit composition:
/// when combining circuits (e.g., Schnorr signature using scalar multiplication),
/// the curve types are checked at compile time, preventing mismatched curves.
///
/// # Type Parameters
///
/// - `C`: A curve configuration implementing [`SWCurveConfig`]
///
/// # Example
///
/// ```
/// use arrabbiata::circuits::gadgets::curve::native::CurveAffineParams;
/// use mina_curves::pasta::PallasParameters;
///
/// // Create params for Pallas curve - compile-time verified as Weierstrass
/// let params = CurveAffineParams::<PallasParameters>::new();
///
/// // Get the curve coefficients
/// use ark_ec::short_weierstrass::SWCurveConfig;
/// use mina_curves::pasta::Fp;
/// assert_eq!(params.coeff_a(), Fp::from(0u64));
/// ```
#[derive(Clone, Debug)]
pub struct CurveAffineParams<C: SWCurveConfig> {
    _marker: PhantomData<C>,
}

impl<C: SWCurveConfig> CurveAffineParams<C> {
    /// Create curve parameters for a short Weierstrass curve in affine form.
    ///
    /// The curve type `C` must implement [`SWCurveConfig`], which guarantees
    /// the curve equation is y² = x³ + ax + b in short Weierstrass form.
    pub fn new() -> Self {
        Self {
            _marker: PhantomData,
        }
    }

    /// Get the coefficient `a` from y² = x³ + ax + b.
    pub fn coeff_a(&self) -> C::BaseField {
        C::COEFF_A
    }

    /// Get the coefficient `b` from y² = x³ + ax + b.
    pub fn coeff_b(&self) -> C::BaseField {
        C::COEFF_B
    }

    /// Check if a point (x, y) in affine coordinates lies on this curve.
    ///
    /// Returns true if y² = x³ + ax + b.
    pub fn is_on_curve(&self, x: C::BaseField, y: C::BaseField) -> bool {
        let y2 = y * y;
        let x3 = x * x * x;
        let ax = C::COEFF_A * x;
        y2 == x3 + ax + C::COEFF_B
    }
}

impl<C: SWCurveConfig> Default for CurveAffineParams<C> {
    fn default() -> Self {
        Self::new()
    }
}

impl<C: SWCurveConfig> PartialEq for CurveAffineParams<C> {
    fn eq(&self, _other: &Self) -> bool {
        // All CurveAffineParams for the same curve type are equal
        true
    }
}

impl<C: SWCurveConfig> Eq for CurveAffineParams<C> {}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ec::AffineRepr;
    use mina_curves::pasta::{Fp, Fq, Pallas, PallasParameters, Vesta, VestaParameters};

    #[test]
    fn test_curve_affine_params_pallas() {
        // Type-safe curve parameters for Pallas
        let params = CurveAffineParams::<PallasParameters>::new();

        // Verify coefficients
        assert_eq!(params.coeff_a(), Fp::from(0u64));
        // Pallas has b = 5
        assert_eq!(params.coeff_b(), Fp::from(5u64));

        // Check generator is on curve
        let g = Pallas::generator();
        assert!(params.is_on_curve(g.x, g.y));

        // Random point should not be on curve
        assert!(!params.is_on_curve(Fp::from(12345u64), Fp::from(67890u64)));
    }

    #[test]
    fn test_curve_affine_params_vesta() {
        // Type-safe curve parameters for Vesta
        let params = CurveAffineParams::<VestaParameters>::new();

        // Verify coefficients (Vesta also has a = 0, b = 5)
        assert_eq!(params.coeff_a(), Fq::from(0u64));
        assert_eq!(params.coeff_b(), Fq::from(5u64));

        // Check generator is on curve
        let g = Vesta::generator();
        assert!(params.is_on_curve(g.x, g.y));
    }

    #[test]
    fn test_curve_affine_params_equality() {
        // All params for the same curve type are equal
        let params1 = CurveAffineParams::<PallasParameters>::new();
        let params2 = CurveAffineParams::<PallasParameters>::new();
        assert_eq!(params1, params2);
    }

    #[test]
    fn test_curve_affine_params_default() {
        // Default implementation works
        let params: CurveAffineParams<PallasParameters> = Default::default();
        assert_eq!(params.coeff_a(), Fp::from(0u64));
    }
}
