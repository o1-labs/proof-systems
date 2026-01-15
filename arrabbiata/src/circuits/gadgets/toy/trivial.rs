//! Trivial gadget that passes through its input unchanged.

use ark_ff::PrimeField;

use crate::{
    circuit::{CircuitEnv, SelectorEnv},
    circuits::{
        gadget::{Position, Row, Scalar, TypedGadget},
        selector::QTrivial,
    },
};

// ============================================================================
// TrivialGadget - Typed Gadget
// ============================================================================

/// A trivial gadget that passes through its input unchanged.
///
/// This implements `TypedGadget` with `Scalar` input/output,
/// enabling type-safe composition with other gadgets via `Chain` and `Repeat`.
///
/// Useful for testing and as a placeholder gadget.
#[derive(Clone, Debug, Default)]
pub struct TrivialGadget;

impl TrivialGadget {
    /// Create a new trivial gadget.
    pub fn new() -> Self {
        Self
    }
}

// TrivialGadget: input at col 0, output is same as input (pass-through)
const TRIVIAL_INPUT_POSITIONS: &[Position] = &[Position {
    col: 0,
    row: Row::Curr,
}];
const TRIVIAL_OUTPUT_POSITIONS: &[Position] = &[Position {
    col: 0,
    row: Row::Curr,
}];

impl<F: PrimeField> TypedGadget<F> for TrivialGadget {
    type Selector = QTrivial;
    type Input<V: Clone> = Scalar<V>;
    type Output<V: Clone> = Scalar<V>;

    const NAME: &'static str = "trivial";
    const DESCRIPTION: &'static str = "Identity circuit: z_{i+1} = z_i";
    const ARITY: usize = 1;
    const ROWS: usize = 1;

    fn input_positions() -> &'static [Position] {
        TRIVIAL_INPUT_POSITIONS
    }

    fn output_positions() -> &'static [Position] {
        // Output is same position as input (pass-through)
        TRIVIAL_OUTPUT_POSITIONS
    }

    fn synthesize<E: CircuitEnv<F> + SelectorEnv<F>>(
        &self,
        _env: &mut E,
        input: Self::Input<E::Variable>,
    ) -> Self::Output<E::Variable> {
        // Pass through unchanged - no constraints
        input
    }

    fn output(&self, input: &Self::Input<F>) -> Self::Output<F> {
        Scalar(input.0)
    }
}

#[cfg(test)]
mod constraint_tests {
    use super::*;
    use crate::circuit::ConstraintEnv;
    use mina_curves::pasta::Fp;

    #[test]
    fn test_trivial_gadget_output() {
        let gadget = TrivialGadget::new();

        let input = Scalar(Fp::from(42u64));
        let output = gadget.output(&input);
        assert_eq!(output.0, input.0);
    }

    #[test]
    fn test_trivial_gadget_constraints() {
        let gadget = TrivialGadget::new();

        let mut env = ConstraintEnv::<Fp>::new();
        let x_var = {
            let pos = env.allocate();
            env.read_position(pos)
        };
        let input = Scalar(x_var);
        let _ = gadget.synthesize(&mut env, input);

        // Trivial gadget has no constraints
        assert_eq!(
            env.num_constraints(),
            0,
            "TrivialGadget should have no constraints"
        );

        // Check all degrees are within MAX_DEGREE (trivially true for 0 constraints)
        env.check_degrees()
            .expect("All constraints should have degree <= MAX_DEGREE");
    }

    /// Regression test for gadget metrics.
    /// If this test fails, the gadget implementation has changed.
    #[test]
    fn test_trivial_gadget_metrics() {
        let gadget = TrivialGadget::new();

        let mut env = ConstraintEnv::<Fp>::new();
        let x_var = {
            let pos = env.allocate();
            env.read_position(pos)
        };
        let input = Scalar(x_var);
        let _ = gadget.synthesize(&mut env, input);

        assert_eq!(env.num_constraints(), 0, "constraints changed");
        assert_eq!(
            env.num_witness_allocations(),
            1,
            "witness allocations changed"
        ); // 1 input
        assert_eq!(env.max_degree(), 0, "max degree changed");
    }
}

/// Trace tests for TrivialGadget.
///
/// This module tests witness generation using the Trace environment.
#[cfg(test)]
mod trace_tests {
    use mina_curves::pasta::Fp;

    use crate::{
        circuit::{CircuitEnv, Trace},
        circuits::gadget::{Scalar, TypedGadget},
    };

    use super::TrivialGadget;

    #[test]
    fn test_trivial_gadget_trace() {
        let gadget = TrivialGadget::new();
        let mut env = Trace::<Fp>::new(16);

        let input_val = Fp::from(42u64);
        let x_pos = env.allocate();
        let x_var = env.write_column(x_pos, input_val);
        let input = Scalar(x_var);
        let output = gadget.synthesize(&mut env, input);

        // Trivial gadget passes through input unchanged
        assert_eq!(output.0, input_val);
        assert_eq!(env.get(0, 0), Some(&input_val));
    }

    #[test]
    fn test_trivial_gadget_chain() {
        let gadget = TrivialGadget::new();
        let mut env = Trace::<Fp>::new(16);

        // Chain multiple steps - output should always equal initial input
        let initial = Fp::from(123u64);
        let mut current = initial;

        for i in 0..5 {
            if i > 0 {
                env.next_row();
            }
            let x_pos = env.allocate();
            let x_var = env.write_column(x_pos, current);
            let input = Scalar(x_var);
            let output = gadget.synthesize(&mut env, input);
            current = output.0;
        }

        // All values should be the same
        assert_eq!(current, initial);
        for row in 0..5 {
            assert_eq!(env.get(row, 0), Some(&initial));
        }
    }

    #[test]
    fn test_trivial_gadget_output_matches() {
        let gadget = TrivialGadget::new();

        let test_values: Vec<u64> = vec![0, 1, 42, 100, 12345];

        for val in test_values {
            let mut env = Trace::<Fp>::new(16);
            let input_val = Fp::from(val);
            let x_pos = env.allocate();
            let x_var = env.write_column(x_pos, input_val);
            let input = Scalar(x_var);

            let synth_output = gadget.synthesize(&mut env, input);
            let direct_output = gadget.output(&Scalar(input_val));

            assert_eq!(synth_output.0, direct_output.0);
            assert_eq!(synth_output.0, input_val);
        }
    }

    /// Verify that output positions correctly describe where outputs are written in the trace.
    #[test]
    fn test_trivial_gadget_output_positions_match_trace() {
        use crate::circuits::gadget::test_utils::verify_trace_positions;

        let gadget = TrivialGadget::new();
        let mut env = Trace::<Fp>::new(16);

        // Input value
        let input_val = Fp::from(42u64);
        let x_pos = env.allocate();
        let x_var = env.write_column(x_pos, input_val);
        let input = Scalar(x_var);

        // Synthesize
        let _output = gadget.synthesize(&mut env, input);

        // Get expected output
        let expected_output = gadget.output(&Scalar(input_val));

        // Verify positions using helper
        let current_row = env.current_row();

        // TrivialGadget has input and output at the same position (pass-through)
        verify_trace_positions(
            &env,
            current_row,
            <TrivialGadget as TypedGadget<Fp>>::input_positions(),
            &[input_val],
            "input",
        );

        verify_trace_positions(
            &env,
            current_row,
            <TrivialGadget as TypedGadget<Fp>>::output_positions(),
            &[expected_output.0],
            "output",
        );
    }
}
