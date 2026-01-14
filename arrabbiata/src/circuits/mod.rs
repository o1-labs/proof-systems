//! Example circuits for the Arrabbiata IVC scheme.
//!
//! This module contains various `StepCircuit` implementations that can be
//! used with the folding scheme. These circuits demonstrate different patterns:
//!
//! - **Basic arithmetic**: `TrivialCircuit`, `SquaringCircuit`, `CubicCircuit`
//! - **Iterative computation**: `FibonacciCircuit`, `MinRootCircuit` (VDF)
//! - **Circuit mixing**: `SignatureCircuit`
//! - **Cryptographic**: `CounterCircuit`, `PoseidonPermutationCircuit`
//! - **Elliptic curve**: `CurveNativeAdd`, `CurveNativeScalarMul`
//! - **IVC Verifier**: `VerifierCircuit` (NIFS commitment absorption)
//!
//! ## Comparison with Microsoft Nova Examples
//!
//! | Nova Example | Arrabbiata Equivalent | Description |
//! |--------------|----------------------|-------------|
//! | minroot.rs | `MinRootCircuit` | VDF computing 5th roots |
//! | and.rs | (use bit gadgets) | Bitwise AND operations |
//!
//! ## Usage
//!
//! ```
//! use arrabbiata::circuits::{FibonacciCircuit, StepCircuit};
//! use mina_curves::pasta::Fp;
//!
//! let circuit = FibonacciCircuit::<Fp>::new();
//! let z0 = [Fp::from(0u64), Fp::from(1u64)];
//! let z1 = circuit.output(&z0); // [1, 1]
//! let z2 = circuit.output(&z1); // [1, 2]
//! assert_eq!(z2, [Fp::from(1u64), Fp::from(2u64)]);
//! ```

pub mod compose;
mod counter;
mod cubic;
pub mod curve;
mod fibonacci;
pub mod gadget;
pub mod hash;
mod minroot;
pub mod selector;
mod signature;
mod square_cubic;
mod squaring;
mod trivial;
pub mod nifs;

pub use counter::{CounterCircuit, StepCounterCircuit};
pub use cubic::CubicCircuit;
pub use curve::{
    CurveAffineParams, CurveNativeAdd, CurveNativeDouble, CurveNativeScalarMul,
    CurveNativeScalarMulStep,
};
pub use fibonacci::{FibonacciCircuit, RepeatedFibonacciCircuit};
pub use minroot::{MinRootCircuit, MinRootIteration};
pub use hash::{
    PoseidonAbsorbCircuit, PoseidonPermutationCircuit, PoseidonRoundCircuit, ROUNDS_PER_ROW,
    ROWS_FOR_PERMUTATION,
};
// TODO: Restore when schnorr.rs is reconstructed
// pub use signature::{SchnorrAdvice, SchnorrCircuit, SignatureAdvice, SignatureCircuit};
pub use square_cubic::SquareCubicCircuit;
pub use squaring::{RepeatedSquaringCircuit, SquaringCircuit};
pub use trivial::TrivialCircuit;
// TODO: Restore when verifier.rs is reconstructed
// pub use nifs::{
//     initial_sponge_state, squeeze_challenge, VerifierCircuit, NUM_CROSS_TERM_COMMITMENTS,
//     NUM_WITNESS_COMMITMENTS, TOTAL_FRESH_COMMITMENTS,
// };

// Re-export selector types
pub use selector::{
    gadget_to_index, index_to_gadget, QApp, QECAdd, QECScale, QNoOp, QPoseidonAbsorb,
    QPoseidonRound, SelectorTag, NUMBER_OF_SELECTOR_TYPES,
};

// Re-export typed gadget types
pub use gadget::{ECPoint, Pair, PoseidonState, Scalar, TypedGadget};

// Re-export composition combinators
pub use compose::{Chain, GadgetCircuit, Repeat, ScalarGadget};

// Re-export the core traits and environments from circuit.rs
pub use crate::circuit::{CircuitEnv, ConstraintEnv, SelectorEnv, StepCircuit, Trace};
