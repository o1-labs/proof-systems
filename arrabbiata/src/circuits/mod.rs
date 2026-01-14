//! Circuits and gadgets for the Arrabbiata IVC scheme.
//!
//! This module contains:
//! - **gadgets**: Various `TypedGadget` implementations (arithmetic, cryptographic, EC)
//! - **compose**: Combinators for composing gadgets (`Chain`, `Repeat`)
//! - **gadget**: The `TypedGadget` trait and typed input/output wrappers
//! - **selector**: Selector type markers for constraint gating
//! - **types**: Advanced circuit value types
//! - **nifs**: NIFS-related circuit components
//!
//! ## Usage
//!
//! ```
//! use arrabbiata::circuits::{FibonacciGadget, Pair, TypedGadget};
//! use mina_curves::pasta::Fp;
//!
//! let gadget = FibonacciGadget::new();
//! let z0 = Pair::new(Fp::from(0u64), Fp::from(1u64));
//! let z1 = gadget.output(&z0); // (1, 1)
//! let z2 = gadget.output(&z1); // (1, 2)
//! assert_eq!(z2.first, Fp::from(1u64));
//! assert_eq!(z2.second, Fp::from(2u64));
//! ```

pub mod compose;
pub mod gadget;
pub mod gadgets;
pub mod nifs;
pub mod selector;
pub mod types;

// Re-export gadgets
pub use gadgets::{
    square_cubic_gadget, CounterGadget, CubicGadget, CurveAffineParams, CurveNativeAddGadget,
    CurveNativeDoubleGadget, CurveNativeScalarMulGadget, CurveNativeScalarMulStepGadget,
    FibonacciGadget, MinRootGadget, PoseidonAbsorbGadget, PoseidonPermutationGadget,
    PoseidonRoundGadget, SquareCubicGadget, SquaringGadget, StepCounterGadget, TrivialGadget,
    ROUNDS_PER_ROW, ROWS_FOR_PERMUTATION, SQUARE_CUBIC_ROWS,
};

// Re-export selector types
pub use selector::{
    gadget_to_index, index_to_gadget, QApp, QCounter, QCubic, QECAdd, QECScale, QFibonacci,
    QMinRoot, QNoOp, QPoseidonAbsorb, QPoseidonKimchiRound, QPoseidonRound, QSquaring, QTrivial,
    SelectorTag, NUMBER_OF_SELECTOR_TYPES,
};

// Re-export typed gadget types
pub use gadget::{
    Commitment, ECPoint, ECPointPair, ECScalarMulInput, ECScalarMulState, Pair, PoseidonState,
    Scalar, SingleCommitment, TypedGadget,
};

// Re-export composition combinators
pub use compose::{
    Chain, GadgetCircuit, PairCircuit, PairGadget, Repeat, ScalarGadget, StateCircuit, StateGadget,
};

// Re-export the core traits and environments from circuit.rs
pub use crate::circuit::{CircuitEnv, ConstraintEnv, SelectorEnv, StepCircuit, Trace};
