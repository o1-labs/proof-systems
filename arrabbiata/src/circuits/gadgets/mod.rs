//! Gadget implementations for the Arrabbiata IVC scheme.
//!
//! This module contains various `TypedGadget` implementations:
//!
//! - **Basic arithmetic**: `TrivialGadget`, `SquaringGadget`, `CubicGadget`
//! - **Iterative computation**: `FibonacciGadget`, `MinRootGadget` (VDF)
//! - **Cryptographic**: `CounterGadget`, `PoseidonPermutationGadget`
//! - **Elliptic curve**: `CurveNativeAddGadget`, `CurveNativeScalarMulGadget`
//! - **Composition**: `SquareCubicGadget`

mod counter;
mod cubic;
pub mod curve;
mod fibonacci;
pub mod hash;
mod minroot;
mod signature;
mod square_cubic;
mod squaring;
mod trivial;

pub use counter::{CounterGadget, StepCounterGadget};
pub use cubic::CubicGadget;
pub use curve::{
    CurveAffineParams, CurveNativeAddGadget, CurveNativeDoubleGadget, CurveNativeScalarMulGadget,
    CurveNativeScalarMulStepGadget,
};
pub use fibonacci::FibonacciGadget;
pub use hash::{
    PoseidonAbsorbGadget, PoseidonKimchiPermutationGadget, PoseidonKimchiRoundGadget,
    PoseidonPermutationGadget, PoseidonRoundGadget, KIMCHI_FULL_ROUNDS, KIMCHI_ROUNDS_PER_ROW,
    KIMCHI_ROWS_FOR_PERMUTATION, ROUNDS_PER_ROW, ROWS_FOR_PERMUTATION,
};
pub use minroot::MinRootGadget;
pub use signature::{
    verify_schnorr_signature, SchnorrHashGadget, SchnorrHashInput, SchnorrHashOutput,
    SchnorrSignature, SchnorrVerifyGadget, SchnorrVerifyInput, SchnorrVerifyOutput,
};
pub use square_cubic::{square_cubic_gadget, SquareCubicGadget, SQUARE_CUBIC_ROWS};
pub use squaring::SquaringGadget;
pub use trivial::TrivialGadget;
