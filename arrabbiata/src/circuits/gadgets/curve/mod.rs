//! Elliptic curve circuit gadgets.
//!
//! This module contains circuit gadgets for elliptic curve operations,
//! organized by field type:
//!
//! - [`native`] - Operations where the curve's base field matches the circuit's
//!   native field. This is the most efficient case.
//!
//! Future additions may include non-native (foreign field) curve operations.

pub mod native;

// Re-export native curve operations for convenience
pub use native::{
    CurveAffineParams, CurveNativeAddGadget, CurveNativeDoubleGadget, CurveNativeScalarMulGadget,
    CurveNativeScalarMulStepGadget,
};
