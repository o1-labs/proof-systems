//! Gadget implementations for the Arrabbiata IVC scheme.
//!
//! This module contains `TypedGadget` implementations organized into:
//!
//! ## NIFS Gadgets (for IVC verifier circuit)
//!
//! These are the actual gadgets used in the Non-Interactive Folding Scheme:
//!
//! - **Hash**: `PoseidonPermutationGadget`, `PoseidonRoundGadget` - Fiat-Shamir
//! - **Elliptic curve**: `CurveNativeAddGadget`, `CurveNativeScalarMulGadget` - commitment ops
//! - **Signature**: `SchnorrVerifyGadget` - signature verification
//! - **Counter**: `CounterGadget`, `StepCounterGadget` - iteration tracking
//! - **VDF**: `MinRootGadget` - verifiable delay function
//!
//! ## Toy Gadgets (for testing and examples)
//!
//! Simple gadgets for testing the API and demonstrating usage:
//!
//! - **Arithmetic**: `TrivialGadget`, `SquaringGadget`, `CubicGadget`
//! - **Iterative**: `FibonacciGadget`
//! - **Composed**: `SquareCubicGadget`

// NIFS gadgets - used in the IVC verifier circuit
mod counter;
pub mod curve;
pub mod hash;
mod minroot;
mod signature;

// Toy gadgets - for testing and examples
pub mod toy;

// Re-export NIFS gadgets
pub use counter::{CounterGadget, StepCounterGadget};
pub use curve::{
    CurveAffineParams, CurveNativeAddGadget, CurveNativeDoubleGadget, CurveNativeScalarMulGadget,
    CurveNativeScalarMulStepGadget,
};
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

// Re-export toy gadgets for convenience
pub use toy::{
    square_cubic_gadget, CubicGadget, FibonacciGadget, PlonkishGadget, SquareCubicGadget,
    SquaringGadget, TrivialGadget, SQUARE_CUBIC_ROWS,
};
