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

use crate::{
    circuit::{CircuitEnv, SelectorEnv},
    circuits::selector::SelectorTag,
};

// Re-export types from types module for convenience
pub use crate::circuits::types::{
    check_arity, Arity, Bit, Bits, Commitment, DoubleCommitment, ECPoint, ECPointPair,
    ECScalarMulInput, ECScalarMulState, FixedVec, HomoPair, Pair, PoseidonState, PoseidonState3,
    Position, Row, Scalar, SingleCommitment,
};

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
/// # Position Layout
///
/// Gadgets declare their input and output positions via `input_positions()` and
/// `output_positions()`. These define where values are read from and written to
/// in the witness table. The length of each position slice must match the arity
/// of the corresponding type:
///
/// ```ignore
/// // Compile-time verification in gadget impl:
/// const _: () = check_arity::<
///     { Self::input_positions().len() },
///     { <Self::Input<()> as Arity>::SIZE }
/// >();
/// ```
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

    /// Input positions in the witness table layout.
    ///
    /// The length of this slice must equal `<Self::Input<()> as Arity>::SIZE`.
    /// Each position specifies a column index and row offset (Curr/Next).
    ///
    /// # Example
    ///
    /// For an EC addition gadget with input `ECPointPair<V>` (arity 4):
    /// ```ignore
    /// fn input_positions() -> &'static [Position] {
    ///     &[
    ///         Position::curr(0),  // x1
    ///         Position::curr(1),  // y1
    ///         Position::curr(2),  // x2
    ///         Position::curr(3),  // y2
    ///     ]
    /// }
    /// ```
    fn input_positions() -> &'static [Position];

    /// Output positions in the witness table layout.
    ///
    /// The length of this slice must equal `<Self::Output<()> as Arity>::SIZE`.
    /// Each position specifies a column index and row offset (Curr/Next).
    ///
    /// # Example
    ///
    /// For an EC addition gadget with output `ECPoint<V>` (arity 2):
    /// ```ignore
    /// fn output_positions() -> &'static [Position] {
    ///     &[
    ///         Position::curr(4),  // x3
    ///         Position::curr(5),  // y3
    ///     ]
    /// }
    /// ```
    fn output_positions() -> &'static [Position];

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
}

// ============================================================================
// Test Utilities
// ============================================================================

/// Test utilities for verifying trace positions.
///
/// This module provides helper functions for testing that gadget implementations
/// correctly write values to their declared positions.
#[cfg(test)]
pub mod test_utils {
    use super::{Position, Row};
    use crate::circuit::Trace;
    use ark_ff::PrimeField;

    /// Verify that trace values at the given positions match expected values.
    ///
    /// This helper function checks that each position in `positions` contains
    /// the corresponding value from `expected_values` in the trace.
    ///
    /// # Arguments
    ///
    /// * `trace` - The trace to verify
    /// * `base_row` - The base row index (typically `trace.current_row()`)
    /// * `positions` - The positions to check (from `input_positions()` or `output_positions()`)
    /// * `expected_values` - The expected values at each position
    /// * `label` - A label for error messages (e.g., "input" or "output")
    ///
    /// # Panics
    ///
    /// Panics if any position contains an unexpected value or if the lengths don't match.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use arrabbiata::circuits::gadget::{test_utils::verify_trace_positions, TypedGadget};
    ///
    /// let output_positions = <MyGadget as TypedGadget<Fp>>::output_positions();
    /// let expected = gadget.output(&input);
    /// verify_trace_positions(&env, env.current_row(), output_positions, &[expected.0], "output");
    /// ```
    pub fn verify_trace_positions<F: PrimeField>(
        trace: &Trace<F>,
        base_row: usize,
        positions: &[Position],
        expected_values: &[F],
        label: &str,
    ) {
        assert_eq!(
            positions.len(),
            expected_values.len(),
            "{} positions count ({}) must match expected values count ({})",
            label,
            positions.len(),
            expected_values.len()
        );

        for (i, (pos, expected)) in positions.iter().zip(expected_values.iter()).enumerate() {
            let row_idx = match pos.row {
                Row::Curr => base_row,
                Row::Next => base_row + 1,
            };
            let actual = trace.get(row_idx, pos.col);
            assert_eq!(
                actual,
                Some(expected),
                "Trace {} position {} (col={}, row={:?}) mismatch: expected {:?}, got {:?}",
                label,
                i,
                pos.col,
                pos.row,
                expected,
                actual
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        circuit::{ConstraintEnv, Trace},
        circuits::selector::QNoOp,
    };
    use mina_curves::pasta::Fp;

    /// A simple squaring gadget for testing.
    #[derive(Clone, Debug)]
    struct TestSquaringGadget;

    // Position constants for TestSquaringGadget
    const TEST_SQUARING_INPUT_POSITIONS: &[Position] = &[Position {
        col: 0,
        row: Row::Curr,
    }];
    const TEST_SQUARING_OUTPUT_POSITIONS: &[Position] = &[Position {
        col: 1,
        row: Row::Curr,
    }];

    impl<F: PrimeField> TypedGadget<F> for TestSquaringGadget {
        type Selector = QNoOp;
        type Input<V: Clone> = Scalar<V>;
        type Output<V: Clone> = Scalar<V>;
        const ROWS: usize = 1;

        fn input_positions() -> &'static [Position] {
            TEST_SQUARING_INPUT_POSITIONS
        }

        fn output_positions() -> &'static [Position] {
            TEST_SQUARING_OUTPUT_POSITIONS
        }

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

    // Compile-time verification that position counts match arities
    const _: () =
        check_arity::<{ TEST_SQUARING_INPUT_POSITIONS.len() }, { <Scalar<()> as Arity>::SIZE }>();
    const _: () =
        check_arity::<{ TEST_SQUARING_OUTPUT_POSITIONS.len() }, { <Scalar<()> as Arity>::SIZE }>();

    #[test]
    fn test_typed_gadget_output() {
        let gadget = TestSquaringGadget;
        let input = Scalar::new(Fp::from(5u64));
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
        let input = Scalar::new(input_var);

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
        let input = Scalar::new(input_var);

        let output = gadget.synthesize(&mut env, input);

        // Output should be 49
        assert_eq!(output.0, Fp::from(49u64));
    }

    #[test]
    fn test_typed_gadget_selector() {
        // Verify the selector type is correct
        assert_eq!(
            <TestSquaringGadget as TypedGadget<Fp>>::Selector::GADGET,
            crate::column::Gadget::NoOp
        );
    }

    #[test]
    fn test_typed_gadget_positions() {
        // Verify input positions
        let input_pos = <TestSquaringGadget as TypedGadget<Fp>>::input_positions();
        assert_eq!(input_pos.len(), 1);
        assert_eq!(input_pos[0], Position::curr(0));

        // Verify output positions
        let output_pos = <TestSquaringGadget as TypedGadget<Fp>>::output_positions();
        assert_eq!(output_pos.len(), 1);
        assert_eq!(output_pos[0], Position::curr(1));

        // Verify position counts match arities
        assert_eq!(
            input_pos.len(),
            <Scalar<()> as Arity>::SIZE,
            "Input positions must match input arity"
        );
        assert_eq!(
            output_pos.len(),
            <Scalar<()> as Arity>::SIZE,
            "Output positions must match output arity"
        );
    }

    #[test]
    fn test_position_constructors() {
        let p1 = Position::curr(5);
        assert_eq!(p1.col, 5);
        assert_eq!(p1.row, Row::Curr);
        assert!(p1.is_curr());
        assert!(!p1.is_next());

        let p2 = Position::next(3);
        assert_eq!(p2.col, 3);
        assert_eq!(p2.row, Row::Next);
        assert!(!p2.is_curr());
        assert!(p2.is_next());

        let p3 = Position::new(7, Row::Curr);
        assert_eq!(p3, Position::curr(7));

        let p4 = Position::new(2, Row::Next);
        assert_eq!(p4, Position::next(2));
    }

    /// Verify that trace values at output positions match expected output.
    #[test]
    fn test_output_positions_match_trace() {
        use super::test_utils::verify_trace_positions;

        let gadget = TestSquaringGadget;
        let mut env = Trace::<Fp>::new(16);

        // Input value
        let input_val = Fp::from(7u64);

        // Allocate and write input
        let input_pos = env.allocate();
        let input_var = env.write_column(input_pos, input_val);
        let input = Scalar::new(input_var);

        // Synthesize
        let _output = gadget.synthesize(&mut env, input);

        // Compute expected output
        let expected_output = gadget.output(&Scalar::new(input_val));

        // Verify positions using helper
        let current_row = env.current_row();

        verify_trace_positions(
            &env,
            current_row,
            <TestSquaringGadget as TypedGadget<Fp>>::input_positions(),
            &[input_val],
            "input",
        );

        verify_trace_positions(
            &env,
            current_row,
            <TestSquaringGadget as TypedGadget<Fp>>::output_positions(),
            &[expected_output.0],
            "output",
        );
    }
}
