//! Squaring gadget: z_{i+1} = z_i^2.

use ark_ff::PrimeField;

use crate::{
    circuit::{CircuitEnv, SelectorEnv},
    circuits::{
        gadget::{Position, Row, Scalar, TypedGadget},
        selector::QSquaring,
    },
};

// ============================================================================
// SquaringGadget - Typed Gadget
// ============================================================================

/// A typed gadget that computes squaring: x -> x^2.
///
/// This implements `TypedGadget` with `Scalar` input/output,
/// enabling type-safe composition with other gadgets via `Chain` and `Repeat`.
#[derive(Clone, Debug, Default)]
pub struct SquaringGadget;

impl SquaringGadget {
    /// Create a new squaring gadget.
    pub fn new() -> Self {
        Self
    }
}

const SQUARING_INPUT_POSITIONS: &[Position] = &[Position {
    col: 0,
    row: Row::Curr,
}];
const SQUARING_OUTPUT_POSITIONS: &[Position] = &[Position {
    col: 1,
    row: Row::Curr,
}];

impl<F: PrimeField> TypedGadget<F> for SquaringGadget {
    type Selector = QSquaring;
    type Input<V: Clone> = Scalar<V>;
    type Output<V: Clone> = Scalar<V>;
    const ROWS: usize = 1;

    fn input_positions() -> &'static [Position] {
        SQUARING_INPUT_POSITIONS
    }

    fn output_positions() -> &'static [Position] {
        SQUARING_OUTPUT_POSITIONS
    }

    fn synthesize<E: CircuitEnv<F> + SelectorEnv<F>>(
        &self,
        env: &mut E,
        input: Self::Input<E::Variable>,
    ) -> Self::Output<E::Variable> {
        let x = input.0.clone();

        // Compute x * x
        let computed = x.clone() * x;

        // Allocate and write the squared value
        let x_squared = {
            let pos = env.allocate();
            env.write_column(pos, computed.clone())
        };

        // Constrain x_squared = x * x (degree 2)
        env.assert_eq_named("squaring", &x_squared, &computed);

        Scalar(x_squared)
    }

    fn output(&self, input: &Self::Input<F>) -> Self::Output<F> {
        Scalar(input.0 * input.0)
    }
}

#[cfg(test)]
mod constraint_tests {
    use super::*;
    use crate::circuit::ConstraintEnv;
    use mina_curves::pasta::Fp;

    #[test]
    fn test_squaring_gadget_output() {
        let gadget = SquaringGadget::new();

        // x -> x^2
        let input = Scalar(Fp::from(2u64));
        let output = gadget.output(&input);
        assert_eq!(output.0, Fp::from(4u64)); // 2^2 = 4

        // Chain: 2 -> 4 -> 16 -> 256
        let output2 = gadget.output(&output);
        assert_eq!(output2.0, Fp::from(16u64));
        let output3 = gadget.output(&output2);
        assert_eq!(output3.0, Fp::from(256u64));
    }

    #[test]
    fn test_squaring_gadget_constraints() {
        let gadget = SquaringGadget::new();

        let mut env = ConstraintEnv::<Fp>::new();
        let x_var = {
            let pos = env.allocate();
            env.read_position(pos)
        };
        let input = Scalar(x_var);
        let _ = gadget.synthesize(&mut env, input);

        // Should have exactly 1 named constraint: x_squared = x * x
        assert_eq!(
            env.num_constraints(),
            1,
            "SquaringGadget should have exactly 1 constraint"
        );
        assert_eq!(
            env.num_named_constraints(),
            1,
            "SquaringGadget should have 1 named constraint"
        );

        // The constraint is: x_squared - x * x = 0
        // x_squared is degree 1, x * x is degree 2
        // So the constraint has degree 2
        let degrees = env.constraint_degrees();
        assert_eq!(degrees[0], 2, "Squaring constraint should have degree 2");

        env.check_degrees()
            .expect("All constraints should have degree <= MAX_DEGREE");
    }

    /// Regression test for gadget metrics.
    /// If this test fails, the gadget implementation has changed.
    #[test]
    fn test_squaring_gadget_metrics() {
        let gadget = SquaringGadget::new();

        let mut env = ConstraintEnv::<Fp>::new();
        let x_var = {
            let pos = env.allocate();
            env.read_position(pos)
        };
        let input = Scalar(x_var);
        let _ = gadget.synthesize(&mut env, input);

        assert_eq!(env.num_constraints(), 1, "constraints changed");
        assert_eq!(
            env.num_witness_allocations(),
            2,
            "witness allocations changed"
        ); // 1 input + 1 output
        assert_eq!(env.max_degree(), 2, "max degree changed");
    }
}

/// Trace tests for SquaringGadget.
///
/// This module tests witness generation using the Trace environment.
#[cfg(test)]
mod trace_tests {
    use mina_curves::pasta::Fp;

    use crate::{
        circuit::{CircuitEnv, Trace},
        circuits::gadget::{Scalar, TypedGadget},
    };

    use super::SquaringGadget;

    #[test]
    fn test_squaring_gadget_trace() {
        let gadget = SquaringGadget::new();
        let mut env = Trace::<Fp>::new(16);

        // Input: 3
        let input_val = Fp::from(3u64);
        let x_pos = env.allocate();
        let x_var = env.write_column(x_pos, input_val);
        let input = Scalar(x_var);

        // Run synthesize
        let output = gadget.synthesize(&mut env, input);

        // Output should be 9 (3^2)
        let expected = gadget.output(&Scalar(input_val));
        assert_eq!(output.0, expected.0);
        assert_eq!(output.0, Fp::from(9u64));

        // Verify the witness table has the input
        assert_eq!(env.get(0, 0), Some(&Fp::from(3u64)));
    }

    #[test]
    fn test_squaring_gadget_chain() {
        let gadget = SquaringGadget::new();
        let mut env = Trace::<Fp>::new(16);

        // Run 3 steps: 2 -> 4 -> 16 -> 256
        let mut current = Fp::from(2u64);
        for i in 0..3 {
            if i > 0 {
                env.next_row();
            }
            let x_pos = env.allocate();
            let x_var = env.write_column(x_pos, current);
            let input = Scalar(x_var);
            let output = gadget.synthesize(&mut env, input);
            current = output.0;
        }

        // Final value should be 256
        assert_eq!(current, Fp::from(256u64));

        // Verify trace (num_rows is domain_size, not filled rows)
        assert_eq!(env.num_rows(), 16);
        assert_eq!(env.current_row(), 2); // We're on the 3rd row (index 2)
    }

    #[test]
    fn test_squaring_gadget_output_matches_for_various_inputs() {
        let gadget = SquaringGadget::new();

        // Test various input values
        let test_values: Vec<u64> = vec![0, 1, 2, 3, 5, 7, 10, 100, 1000, 12345];

        for val in test_values {
            let mut env = Trace::<Fp>::new(16);
            let input_val = Fp::from(val);
            let x_pos = env.allocate();
            let x_var = env.write_column(x_pos, input_val);
            let input = Scalar(x_var);

            let synth_output = gadget.synthesize(&mut env, input);
            let direct_output = gadget.output(&Scalar(input_val));

            assert_eq!(
                synth_output.0, direct_output.0,
                "synthesize output should match output() for input {}",
                val
            );
            assert_eq!(
                synth_output.0,
                Fp::from(val * val),
                "output should be {} for input {}",
                val * val,
                val
            );
        }
    }

    #[test]
    fn test_squaring_gadget_witness_table_structure() {
        let gadget = SquaringGadget::new();
        let mut env = Trace::<Fp>::new(16);

        // Input: 5
        let input_val = Fp::from(5u64);
        let x_pos = env.allocate();
        let x_var = env.write_column(x_pos, input_val);
        let input = Scalar(x_var);
        let output = gadget.synthesize(&mut env, input);

        // Check witness table structure:
        // Column 0: input (5)
        // Column 1: allocated witness (x_squared = 25)
        assert_eq!(
            env.get(0, 0),
            Some(&Fp::from(5u64)),
            "Column 0 should have input"
        );
        assert_eq!(
            env.get(0, 1),
            Some(&Fp::from(25u64)),
            "Column 1 should have x_squared witness"
        );
        assert_eq!(output.0, Fp::from(25u64), "Output should be 25");
    }

    #[test]
    fn test_squaring_gadget_zero_input() {
        let gadget = SquaringGadget::new();
        let mut env = Trace::<Fp>::new(16);

        // 0^2 = 0
        let x_pos = env.allocate();
        let x_var = env.write_column(x_pos, Fp::from(0u64));
        let input = Scalar(x_var);
        let output = gadget.synthesize(&mut env, input);

        assert_eq!(output.0, Fp::from(0u64));
        assert_eq!(env.get(0, 0), Some(&Fp::from(0u64)));
        assert_eq!(env.get(0, 1), Some(&Fp::from(0u64)));
    }

    #[test]
    fn test_squaring_gadget_one_input() {
        let gadget = SquaringGadget::new();
        let mut env = Trace::<Fp>::new(16);

        // 1^2 = 1
        let x_pos = env.allocate();
        let x_var = env.write_column(x_pos, Fp::from(1u64));
        let input = Scalar(x_var);
        let output = gadget.synthesize(&mut env, input);

        assert_eq!(output.0, Fp::from(1u64));
        assert_eq!(env.get(0, 0), Some(&Fp::from(1u64)));
        assert_eq!(env.get(0, 1), Some(&Fp::from(1u64)));
    }

    /// Verify that output positions correctly describe where outputs are written in the trace.
    #[test]
    fn test_squaring_gadget_output_positions_match_trace() {
        use crate::circuits::gadget::{test_utils::verify_trace_positions, TypedGadget};

        let gadget = SquaringGadget::new();
        let mut env = Trace::<Fp>::new(16);

        // Input value
        let input_val = Fp::from(5u64);
        let x_pos = env.allocate();
        let x_var = env.write_column(x_pos, input_val);
        let input = Scalar(x_var);

        // Synthesize
        let _output = gadget.synthesize(&mut env, input);

        // Get expected output
        let expected_output = gadget.output(&Scalar(input_val));

        // Verify positions using helper
        let current_row = env.current_row();

        verify_trace_positions(
            &env,
            current_row,
            <SquaringGadget as TypedGadget<Fp>>::input_positions(),
            &[input_val],
            "input",
        );

        verify_trace_positions(
            &env,
            current_row,
            <SquaringGadget as TypedGadget<Fp>>::output_positions(),
            &[expected_output.0],
            "output",
        );
    }
}
