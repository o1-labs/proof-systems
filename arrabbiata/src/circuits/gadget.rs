//! Typed gadget trait for type-safe circuit composition.
//!
//! This module provides the `TypedGadget` trait which enables:
//! - Type-safe input/output for gadgets
//! - Compile-time verification of gadget compatibility
//! - Automatic selector gating
//!
//! # Example
//!
//! ```
//! use arrabbiata::circuits::gadget::{TypedGadget, Scalar};
//! use arrabbiata::circuits::selector::QNoOp;
//! use arrabbiata::circuit::{CircuitEnv, SelectorEnv};
//! use ark_ff::PrimeField;
//!
//! #[derive(Clone, Debug)]
//! struct SquaringGadget;
//!
//! impl<F: PrimeField> TypedGadget<F> for SquaringGadget {
//!     type Selector = QNoOp;
//!     type Input<V: Clone> = Scalar<V>;
//!     type Output<V: Clone> = Scalar<V>;
//!     const ROWS: usize = 1;
//!
//!     fn synthesize<E: CircuitEnv<F> + SelectorEnv<F>>(
//!         &self,
//!         env: &mut E,
//!         input: Self::Input<E::Variable>,
//!     ) -> Self::Output<E::Variable> {
//!         let x = input.0;
//!         let x_squared = x.clone() * x;
//!         let pos = env.allocate();
//!         let out = env.write_column(pos, x_squared);
//!         Scalar(out)
//!     }
//!
//!     fn output(&self, input: &Self::Input<F>) -> Self::Output<F> {
//!         let x = input.0;
//!         Scalar(x * x)
//!     }
//! }
//! ```

use ark_ff::PrimeField;
use core::fmt::Debug;

use crate::circuit::{CircuitEnv, SelectorEnv};
use crate::circuits::selector::SelectorTag;

// ============================================================================
// Typed Value Wrappers
// ============================================================================

/// A single scalar value (field element).
#[derive(Clone, Debug)]
pub struct Scalar<V>(pub V);

impl<V: Clone> From<V> for Scalar<V> {
    fn from(v: V) -> Self {
        Scalar(v)
    }
}

/// A pair of values.
#[derive(Clone, Debug)]
pub struct Pair<V>(pub V, pub V);

impl<V: Clone> From<(V, V)> for Pair<V> {
    fn from((a, b): (V, V)) -> Self {
        Pair(a, b)
    }
}

/// An elliptic curve point (x, y coordinates).
#[derive(Clone, Debug)]
pub struct ECPoint<V> {
    pub x: V,
    pub y: V,
}

impl<V: Clone> ECPoint<V> {
    pub fn new(x: V, y: V) -> Self {
        Self { x, y }
    }
}

impl<V: Clone> From<(V, V)> for ECPoint<V> {
    fn from((x, y): (V, V)) -> Self {
        ECPoint { x, y }
    }
}

/// Poseidon sponge state (3 field elements for width-3 sponge).
#[derive(Clone, Debug)]
pub struct PoseidonState<V> {
    pub state: [V; 3],
}

impl<V: Clone> PoseidonState<V> {
    pub fn new(state: [V; 3]) -> Self {
        Self { state }
    }
}

impl<V: Clone> From<[V; 3]> for PoseidonState<V> {
    fn from(state: [V; 3]) -> Self {
        PoseidonState { state }
    }
}

// ============================================================================
// TypedGadget Trait
// ============================================================================

/// A gadget with strongly typed input and output.
///
/// This trait enables type-safe gadget composition where the compiler
/// verifies that outputs of one gadget are compatible with inputs of the next.
///
/// # Type Parameters
///
/// - `F`: The prime field for circuit values
///
/// # Associated Types
///
/// - `Selector`: The selector type for this gadget (e.g., `QApp`, `QECAdd`)
/// - `Input<V>`: The input type, parameterized by variable type
/// - `Output<V>`: The output type, parameterized by variable type
///
/// # Associated Constants
///
/// - `ROWS`: Number of rows this gadget occupies
///
/// # Design Notes
///
/// The `Input<V>` and `Output<V>` types are parameterized by the variable type `V`
/// to support both:
/// - Symbolic mode: `V = Expr<F>` for constraint generation
/// - Concrete mode: `V = F` for witness generation
pub trait TypedGadget<F: PrimeField>: Clone + Debug + Send + Sync {
    /// The selector type for this gadget.
    type Selector: SelectorTag;

    /// Input type, parameterized by variable type.
    type Input<V: Clone>: Clone;

    /// Output type, parameterized by variable type.
    type Output<V: Clone>: Clone;

    /// Number of rows this gadget uses.
    const ROWS: usize;

    /// Synthesize constraints for this gadget.
    ///
    /// The constraints are automatically gated by the gadget's selector.
    fn synthesize<E: CircuitEnv<F> + SelectorEnv<F>>(
        &self,
        env: &mut E,
        input: Self::Input<E::Variable>,
    ) -> Self::Output<E::Variable>;

    /// Compute the output for witness generation.
    fn output(&self, input: &Self::Input<F>) -> Self::Output<F>;

    /// Get the gadget's selector.
    fn gadget(&self) -> crate::column::Gadget {
        Self::Selector::GADGET
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuit::{ConstraintEnv, Trace};
    use crate::circuits::selector::QNoOp;
    use mina_curves::pasta::Fp;

    /// A simple squaring gadget for testing.
    #[derive(Clone, Debug)]
    struct TestSquaringGadget;

    impl<F: PrimeField> TypedGadget<F> for TestSquaringGadget {
        type Selector = QNoOp;
        type Input<V: Clone> = Scalar<V>;
        type Output<V: Clone> = Scalar<V>;
        const ROWS: usize = 1;

        fn synthesize<E: CircuitEnv<F> + SelectorEnv<F>>(
            &self,
            env: &mut E,
            input: Self::Input<E::Variable>,
        ) -> Self::Output<E::Variable> {
            let x = input.0;
            let x_squared = x.clone() * x;

            // Allocate output
            let out = {
                let pos = env.allocate();
                env.write_column(pos, x_squared)
            };

            Scalar(out)
        }

        fn output(&self, input: &Self::Input<F>) -> Self::Output<F> {
            let x = input.0;
            Scalar(x * x)
        }
    }

    #[test]
    fn test_typed_gadget_output() {
        let gadget = TestSquaringGadget;
        let input = Scalar(Fp::from(5u64));
        let output = gadget.output(&input);
        assert_eq!(output.0, Fp::from(25u64));
    }

    #[test]
    fn test_typed_gadget_synthesize_constraint() {
        let gadget = TestSquaringGadget;
        let mut env = ConstraintEnv::<Fp>::new();

        // Create input variable
        let input_pos = env.allocate();
        let input_var = env.read_position(input_pos);
        let input = Scalar(input_var);

        let _output = gadget.synthesize(&mut env, input);

        // Should have allocated one witness (the output)
        assert_eq!(env.num_witness_allocations(), 2); // input + output
    }

    #[test]
    fn test_typed_gadget_synthesize_trace() {
        let gadget = TestSquaringGadget;
        let mut env = Trace::<Fp>::new(16);

        // Write input value
        let input_pos = env.allocate();
        let input_var = env.write_column(input_pos, Fp::from(7u64));
        let input = Scalar(input_var);

        let output = gadget.synthesize(&mut env, input);

        // Output should be 49
        assert_eq!(output.0, Fp::from(49u64));
    }

    #[test]
    fn test_typed_gadget_selector() {
        let gadget = TestSquaringGadget;
        assert_eq!(TypedGadget::<Fp>::gadget(&gadget), crate::column::Gadget::NoOp);
    }
}
