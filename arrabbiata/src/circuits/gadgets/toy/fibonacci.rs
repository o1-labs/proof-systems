//! Fibonacci gadget for computing the Fibonacci sequence.
//!
//! This module provides `FibonacciGadget`: A single Fibonacci step as a `TypedGadget`.
//!
//! The Fibonacci relation computes: (x, y) -> (y, x + y)
//!
//! For multiple iterations per fold, use `Repeat<FibonacciGadget, N>` from the compose module.

use ark_ff::PrimeField;

use crate::{
    circuit::{CircuitEnv, SelectorEnv},
    circuits::{
        gadget::{Pair, Position, Row, TypedGadget},
        selector::QFibonacci,
    },
};

// ============================================================================
// FibonacciGadget - Single Step TypedGadget
// ============================================================================

/// A single Fibonacci step as a typed gadget.
///
/// Computes: (x, y) -> (y, x + y)
///
/// This is a purely deterministic gadget - no advice needed.
///
/// # Example
///
/// ```
/// use arrabbiata::circuits::{FibonacciGadget, Pair, TypedGadget};
/// use mina_curves::pasta::Fp;
///
/// let gadget = FibonacciGadget;
///
/// // Fibonacci: (0, 1) -> (1, 1) -> (1, 2) -> (2, 3) -> ...
/// let input = Pair::new(Fp::from(0u64), Fp::from(1u64));
/// let output = gadget.output(&input);
/// assert_eq!(output.first, Fp::from(1u64));  // y
/// assert_eq!(output.second, Fp::from(1u64)); // x + y
/// ```
#[derive(Clone, Debug, Default)]
pub struct FibonacciGadget;

impl FibonacciGadget {
    /// Create a new Fibonacci gadget.
    pub fn new() -> Self {
        Self
    }
}

// Fibonacci layout:
// Input: (x, y) at columns 0, 1
// Output: (y, x+y) at columns 2, 3
const FIBONACCI_INPUT_POSITIONS: &[Position] = &[
    Position {
        col: 0,
        row: Row::Curr,
    }, // x
    Position {
        col: 1,
        row: Row::Curr,
    }, // y
];
const FIBONACCI_OUTPUT_POSITIONS: &[Position] = &[
    Position {
        col: 2,
        row: Row::Curr,
    }, // out0 = y
    Position {
        col: 3,
        row: Row::Curr,
    }, // out1 = x + y
];

impl<F: PrimeField> TypedGadget<F> for FibonacciGadget {
    type Selector = QFibonacci;
    type Input<V: Clone> = Pair<V>;
    type Output<V: Clone> = Pair<V>;

    const NAME: &'static str = "fibonacci";
    const DESCRIPTION: &'static str = "Fibonacci sequence: (x, y) -> (y, x + y)";
    const ARITY: usize = 2;
    const ROWS: usize = 1;

    fn input_positions() -> &'static [Position] {
        FIBONACCI_INPUT_POSITIONS
    }

    fn output_positions() -> &'static [Position] {
        FIBONACCI_OUTPUT_POSITIONS
    }

    fn synthesize<E: CircuitEnv<F> + SelectorEnv<F>>(
        &self,
        env: &mut E,
        input: Self::Input<E::Variable>,
    ) -> Self::Output<E::Variable> {
        let x = input.first;
        let y = input.second;

        // Compute x + y
        let sum = x + y.clone();

        // Allocate and write outputs
        let out0 = {
            let pos = env.allocate();
            env.write_column(pos, y.clone())
        };
        let out1 = {
            let pos = env.allocate();
            env.write_column(pos, sum.clone())
        };

        // Constrain outputs
        env.assert_eq_named("fib_out0", &out0, &y); // degree 1
        env.assert_eq_named("fib_out1", &out1, &sum); // degree 1

        Pair::new(out0, out1)
    }

    fn output(&self, input: &Self::Input<F>) -> Self::Output<F> {
        let x = input.first;
        let y = input.second;
        Pair::new(y, x + y)
    }
}

/// Tests for FibonacciGadget (constraint generation).
#[cfg(test)]
mod gadget_tests {
    use mina_curves::pasta::Fp;

    use crate::{
        circuit::{CircuitEnv, ConstraintEnv, Trace},
        circuits::gadget::{Pair, TypedGadget},
    };

    use super::FibonacciGadget;

    #[test]
    fn test_fibonacci_gadget_output() {
        let gadget = FibonacciGadget;

        // (0, 1) -> (1, 1)
        let input = Pair::new(Fp::from(0u64), Fp::from(1u64));
        let output = gadget.output(&input);
        assert_eq!(output.first, Fp::from(1u64));
        assert_eq!(output.second, Fp::from(1u64));

        // (1, 1) -> (1, 2)
        let input = Pair::new(Fp::from(1u64), Fp::from(1u64));
        let output = gadget.output(&input);
        assert_eq!(output.first, Fp::from(1u64));
        assert_eq!(output.second, Fp::from(2u64));

        // (3, 5) -> (5, 8)
        let input = Pair::new(Fp::from(3u64), Fp::from(5u64));
        let output = gadget.output(&input);
        assert_eq!(output.first, Fp::from(5u64));
        assert_eq!(output.second, Fp::from(8u64));
    }

    #[test]
    fn test_fibonacci_gadget_chain() {
        let gadget = FibonacciGadget;

        // Chain: (0, 1) -> (1, 1) -> (1, 2) -> (2, 3) -> (3, 5) -> (5, 8)
        let mut current = Pair::new(Fp::from(0u64), Fp::from(1u64));
        for _ in 0..5 {
            current = gadget.output(&current);
        }
        assert_eq!(current.first, Fp::from(5u64));
        assert_eq!(current.second, Fp::from(8u64));
    }

    #[test]
    fn test_fibonacci_gadget_constraint_env() {
        let gadget = FibonacciGadget;

        let mut env = ConstraintEnv::<Fp>::new();
        let x_var = {
            let pos = env.allocate();
            env.read_position(pos)
        };
        let y_var = {
            let pos = env.allocate();
            env.read_position(pos)
        };
        let input = Pair::new(x_var, y_var);

        let _output = gadget.synthesize(&mut env, input);

        // Should have 2 constraints (fib_out0, fib_out1)
        assert_eq!(env.num_constraints(), 2);
        assert_eq!(env.num_named_constraints(), 2);

        // Both constraints have degree 1
        assert_eq!(env.max_degree(), 1);
    }

    #[test]
    fn test_fibonacci_gadget_trace() {
        let gadget = FibonacciGadget;

        let mut env = Trace::<Fp>::new(16);

        // Write input variables
        let x_pos = env.allocate();
        let x_var = env.write_column(x_pos, Fp::from(3u64));
        let y_pos = env.allocate();
        let y_var = env.write_column(y_pos, Fp::from(5u64));
        let input = Pair::new(x_var, y_var);

        let output = gadget.synthesize(&mut env, input);

        // (3, 5) -> (5, 8)
        assert_eq!(output.first, Fp::from(5u64));
        assert_eq!(output.second, Fp::from(8u64));
    }

    #[test]
    fn test_fibonacci_gadget_rows() {
        // FibonacciGadget should use 1 row
        assert_eq!(<FibonacciGadget as TypedGadget<Fp>>::ROWS, 1);
    }

    #[test]
    fn test_fibonacci_gadget_various_inputs() {
        let gadget = FibonacciGadget;

        let test_pairs: Vec<(u64, u64)> =
            vec![(0, 1), (1, 1), (1, 2), (3, 5), (8, 13), (0, 0), (100, 200)];

        for (x_val, y_val) in test_pairs {
            let x = Fp::from(x_val);
            let y = Fp::from(y_val);
            let input = Pair::new(x, y);

            let output = gadget.output(&input);

            // Verify Fibonacci relation: (x, y) -> (y, x + y)
            assert_eq!(
                output.first, y,
                "first output should be y for ({}, {})",
                x_val, y_val
            );
            assert_eq!(
                output.second,
                x + y,
                "second output should be x + y for ({}, {})",
                x_val,
                y_val
            );
        }
    }

    #[test]
    fn test_fibonacci_gadget_synthesize_matches_output() {
        let gadget = FibonacciGadget;

        let test_pairs: Vec<(u64, u64)> = vec![(0, 1), (3, 5), (8, 13)];

        for (x_val, y_val) in test_pairs {
            let mut env = Trace::<Fp>::new(16);

            let x = Fp::from(x_val);
            let y = Fp::from(y_val);

            let x_pos = env.allocate();
            let x_var = env.write_column(x_pos, x);
            let y_pos = env.allocate();
            let y_var = env.write_column(y_pos, y);
            let input = Pair::new(x_var, y_var);

            let synth_output = gadget.synthesize(&mut env, input);
            let direct_output = gadget.output(&Pair::new(x, y));

            assert_eq!(synth_output.first, direct_output.first);
            assert_eq!(synth_output.second, direct_output.second);
        }
    }

    /// Verify that output positions correctly describe where outputs are written in the trace.
    #[test]
    fn test_fibonacci_gadget_output_positions_match_trace() {
        use crate::circuits::gadget::{test_utils::verify_trace_positions, TypedGadget};

        let gadget = FibonacciGadget;
        let mut env = Trace::<Fp>::new(16);

        // Input values: (3, 5) -> (5, 8)
        let x_val = Fp::from(3u64);
        let y_val = Fp::from(5u64);

        // Write inputs at declared input positions
        let x_pos = env.allocate();
        let x_var = env.write_column(x_pos, x_val);
        let y_pos = env.allocate();
        let y_var = env.write_column(y_pos, y_val);
        let input = Pair::new(x_var, y_var);

        // Synthesize
        let _output = gadget.synthesize(&mut env, input);

        // Get expected output
        let expected_output = gadget.output(&Pair::new(x_val, y_val));

        // Verify positions using helper
        let current_row = env.current_row();

        verify_trace_positions(
            &env,
            current_row,
            <FibonacciGadget as TypedGadget<Fp>>::input_positions(),
            &[x_val, y_val],
            "input",
        );

        verify_trace_positions(
            &env,
            current_row,
            <FibonacciGadget as TypedGadget<Fp>>::output_positions(),
            &[expected_output.first, expected_output.second],
            "output",
        );
    }
}
