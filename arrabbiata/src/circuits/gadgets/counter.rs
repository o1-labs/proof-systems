//! Counter gadgets - simple incrementing counters.
//!
//! This module provides:
//! - `CounterGadget`: Increments by 1 each step
//! - `StepCounterGadget`: Increments by a configurable step size
//!
//! These are the simplest non-trivial gadgets, useful as baseline benchmarks.
//!
//! After N iterations: output = input + N (for CounterGadget)

use ark_ff::PrimeField;

use crate::{
    circuit::{CircuitEnv, SelectorEnv},
    circuits::{
        gadget::{Position, Row, Scalar, TypedGadget},
        selector::QCounter,
    },
};

// ============================================================================
// CounterGadget - Typed Gadget (increment by 1)
// ============================================================================

/// A simple counter gadget that increments by 1 each step.
///
/// This implements `TypedGadget` with `Scalar` input/output,
/// enabling type-safe composition with other gadgets via `Chain` and `Repeat`.
#[derive(Clone, Debug, Default)]
pub struct CounterGadget;

impl CounterGadget {
    /// Create a new counter gadget.
    pub fn new() -> Self {
        Self
    }
}

const COUNTER_INPUT_POSITIONS: &[Position] = &[Position {
    col: 0,
    row: Row::Curr,
}];
const COUNTER_OUTPUT_POSITIONS: &[Position] = &[Position {
    col: 1,
    row: Row::Curr,
}];

impl<F: PrimeField> TypedGadget<F> for CounterGadget {
    type Selector = QCounter;
    type Input<V: Clone> = Scalar<V>;
    type Output<V: Clone> = Scalar<V>;
    const ROWS: usize = 1;

    fn input_positions() -> &'static [Position] {
        COUNTER_INPUT_POSITIONS
    }

    fn output_positions() -> &'static [Position] {
        COUNTER_OUTPUT_POSITIONS
    }

    fn synthesize<E: CircuitEnv<F> + SelectorEnv<F>>(
        &self,
        env: &mut E,
        input: Self::Input<E::Variable>,
    ) -> Self::Output<E::Variable> {
        let counter = input.0;
        let one = env.one();
        let incremented = counter + one;

        // Allocate and write computed value
        let output = {
            let pos = env.allocate();
            env.write_column(pos, incremented.clone())
        };
        env.assert_eq(&output, &incremented);

        Scalar(output)
    }

    fn output(&self, input: &Self::Input<F>) -> Self::Output<F> {
        Scalar(input.0 + F::from(1u64))
    }
}

// ============================================================================
// StepCounterGadget - Typed Gadget (increment by configurable step)
// ============================================================================

/// A counter gadget that increments by a configurable step size.
///
/// This implements `TypedGadget` with `Scalar` input/output,
/// enabling type-safe composition with other gadgets via `Chain` and `Repeat`.
#[derive(Clone, Debug)]
pub struct StepCounterGadget<F: PrimeField> {
    step_size: F,
}

impl<F: PrimeField> StepCounterGadget<F> {
    /// Create a counter gadget that increments by the given step size.
    pub fn new(step_size: F) -> Self {
        Self { step_size }
    }
}

const STEP_COUNTER_INPUT_POSITIONS: &[Position] = &[Position {
    col: 0,
    row: Row::Curr,
}];
const STEP_COUNTER_OUTPUT_POSITIONS: &[Position] = &[Position {
    col: 1,
    row: Row::Curr,
}];

impl<F: PrimeField> TypedGadget<F> for StepCounterGadget<F> {
    type Selector = QCounter;
    type Input<V: Clone> = Scalar<V>;
    type Output<V: Clone> = Scalar<V>;
    const ROWS: usize = 1;

    fn input_positions() -> &'static [Position] {
        STEP_COUNTER_INPUT_POSITIONS
    }

    fn output_positions() -> &'static [Position] {
        STEP_COUNTER_OUTPUT_POSITIONS
    }

    fn synthesize<E: CircuitEnv<F> + SelectorEnv<F>>(
        &self,
        env: &mut E,
        input: Self::Input<E::Variable>,
    ) -> Self::Output<E::Variable> {
        let counter = input.0;
        let step = env.constant(self.step_size);
        let incremented = counter + step;

        // Allocate and write computed value
        let output = {
            let pos = env.allocate();
            env.write_column(pos, incremented.clone())
        };
        env.assert_eq(&output, &incremented);

        Scalar(output)
    }

    fn output(&self, input: &Self::Input<F>) -> Self::Output<F> {
        Scalar(input.0 + self.step_size)
    }
}

#[cfg(test)]
mod constraint_tests {
    use super::*;
    use crate::circuit::ConstraintEnv;
    use mina_curves::pasta::Fp;
    use rand::{Rng, SeedableRng};

    #[test]
    fn test_counter_gadget_output() {
        let gadget = CounterGadget::new();
        let input = Scalar(Fp::from(0u64));

        let output = gadget.output(&input);
        assert_eq!(output.0, Fp::from(1u64));
    }

    #[test]
    fn test_counter_gadget_iterations() {
        let gadget = CounterGadget::new();
        let mut current = Scalar(Fp::from(0u64));

        for i in 1..=100 {
            current = gadget.output(&current);
            assert_eq!(current.0, Fp::from(i as u64));
        }
    }

    #[test]
    fn test_counter_gadget_constraints() {
        let gadget = CounterGadget::new();

        let mut env = ConstraintEnv::<Fp>::new();
        let x_var = {
            let pos = env.allocate();
            env.read_position(pos)
        };
        let input = Scalar(x_var);
        let _ = gadget.synthesize(&mut env, input);

        // Counter gadget has 1 constraint: output = input + 1
        assert_eq!(
            env.num_constraints(),
            1,
            "CounterGadget should have exactly 1 constraint"
        );

        // The constraint is: output - (counter + 1) = 0
        // output is degree 1, counter + 1 is degree 1
        // So the constraint has degree 1
        let degrees = env.constraint_degrees();
        assert_eq!(degrees[0], 1, "Counter constraint should have degree 1");

        env.check_degrees()
            .expect("All constraints should have degree <= MAX_DEGREE");
    }

    /// Regression test for gadget metrics.
    /// If this test fails, the gadget implementation has changed.
    #[test]
    fn test_counter_gadget_metrics() {
        let gadget = CounterGadget::new();

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
        assert_eq!(env.max_degree(), 1, "max degree changed");
    }

    #[test]
    fn test_step_counter_gadget() {
        let gadget = StepCounterGadget::<Fp>::new(Fp::from(5u64));
        let mut current = Scalar(Fp::from(0u64));

        for i in 1..=10 {
            current = gadget.output(&current);
            assert_eq!(current.0, Fp::from(i * 5));
        }
    }

    #[test]
    fn test_step_counter_gadget_constraints() {
        let gadget = StepCounterGadget::<Fp>::new(Fp::from(5u64));

        let mut env = ConstraintEnv::<Fp>::new();
        let x_var = {
            let pos = env.allocate();
            env.read_position(pos)
        };
        let input = Scalar(x_var);
        let _ = gadget.synthesize(&mut env, input);

        // StepCounterGadget has 1 constraint: output = input + step
        assert_eq!(
            env.num_constraints(),
            1,
            "StepCounterGadget should have exactly 1 constraint"
        );

        assert_eq!(
            env.num_witness_allocations(),
            2, // 1 input + 1 output
            "StepCounterGadget should have 2 witness allocations"
        );

        // The constraint is linear (degree 1)
        let degrees = env.constraint_degrees();
        assert_eq!(degrees[0], 1, "StepCounter constraint should have degree 1");

        env.check_degrees()
            .expect("All constraints should have degree <= MAX_DEGREE");
    }

    /// Regression test for StepCounterGadget metrics.
    #[test]
    fn test_step_counter_gadget_metrics() {
        let gadget = StepCounterGadget::<Fp>::new(Fp::from(7u64));

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
        assert_eq!(env.max_degree(), 1, "max degree changed");
    }

    /// Test CounterGadget with random starting value.
    #[test]
    fn test_counter_gadget_random_starting_value() {
        let seed: u64 = rand::random();
        println!("test_counter_gadget_random_starting_value seed: {seed}");
        let mut rng = rand::rngs::StdRng::seed_from_u64(seed);

        let gadget = CounterGadget::new();

        let val: u64 = rng.gen();
        let input = Scalar(Fp::from(val));
        let output = gadget.output(&input);
        assert_eq!(output.0, Fp::from(val) + Fp::from(1u64));
    }

    /// Test StepCounterGadget with random step size.
    #[test]
    fn test_step_counter_gadget_random_step() {
        let seed: u64 = rand::random();
        println!("test_step_counter_gadget_random_step seed: {seed}");
        let mut rng = rand::rngs::StdRng::seed_from_u64(seed);

        // Generate random non-zero step size
        let step: u64 = rng.gen_range(1..1_000_000);
        let gadget = StepCounterGadget::<Fp>::new(Fp::from(step));

        // Test output with random starting value
        let start: u64 = rng.gen();
        let input = Scalar(Fp::from(start));
        let output = gadget.output(&input);
        assert_eq!(output.0, Fp::from(start) + Fp::from(step));

        // Test constraints
        let mut env = ConstraintEnv::<Fp>::new();
        let x_var = {
            let pos = env.allocate();
            env.read_position(pos)
        };
        let input = Scalar(x_var);
        let _ = gadget.synthesize(&mut env, input);

        assert_eq!(
            env.num_constraints(),
            1,
            "StepCounterGadget should have 1 constraint for step size {}",
            step
        );
        assert_eq!(
            env.max_degree(),
            1,
            "StepCounterGadget should have max degree 1 for step size {}",
            step
        );
    }

    /// Test that CounterGadget and StepCounterGadget(1) produce same results.
    #[test]
    fn test_counter_gadget_equivalence() {
        let counter = CounterGadget::new();
        let step_counter = StepCounterGadget::<Fp>::new(Fp::from(1u64));

        let mut c1 = Scalar(Fp::from(0u64));
        let mut c2 = Scalar(Fp::from(0u64));

        for _ in 0..10 {
            c1 = counter.output(&c1);
            c2 = step_counter.output(&c2);
            assert_eq!(
                c1.0, c2.0,
                "CounterGadget and StepCounterGadget(1) should match"
            );
        }
    }
}

/// Trace tests for CounterGadget.
///
/// This module tests witness generation using the Trace environment.
#[cfg(test)]
mod trace_tests {
    use mina_curves::pasta::Fp;

    use crate::{
        circuit::{CircuitEnv, Trace},
        circuits::gadget::{Scalar, TypedGadget},
    };

    use super::{CounterGadget, StepCounterGadget};

    #[test]
    fn test_counter_gadget_trace() {
        let gadget = CounterGadget::new();
        let mut env = Trace::<Fp>::new(16);

        let input_val = Fp::from(0u64);
        let x_pos = env.allocate();
        let x_var = env.write_column(x_pos, input_val);
        let input = Scalar(x_var);
        let output = gadget.synthesize(&mut env, input);

        // Output should be input + 1
        assert_eq!(output.0, Fp::from(1u64));
        assert_eq!(env.get(0, 0), Some(&Fp::from(0u64)));
    }

    #[test]
    fn test_counter_gadget_chain() {
        let gadget = CounterGadget::new();
        let mut env = Trace::<Fp>::new(16);

        // Chain multiple steps: 0 -> 1 -> 2 -> 3 -> 4 -> 5
        let mut current = Fp::from(0u64);

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

        // Final value should be 5
        assert_eq!(current, Fp::from(5u64));

        // Verify trace
        for row in 0..5 {
            assert_eq!(env.get(row, 0), Some(&Fp::from(row as u64)));
        }
    }

    #[test]
    fn test_counter_gadget_output_matches() {
        let gadget = CounterGadget::new();

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
            assert_eq!(synth_output.0, Fp::from(val + 1));
        }
    }

    #[test]
    fn test_step_counter_gadget_trace() {
        let gadget = StepCounterGadget::<Fp>::new(Fp::from(5u64));
        let mut env = Trace::<Fp>::new(16);

        let input_val = Fp::from(0u64);
        let x_pos = env.allocate();
        let x_var = env.write_column(x_pos, input_val);
        let input = Scalar(x_var);
        let output = gadget.synthesize(&mut env, input);

        // Output should be input + 5
        assert_eq!(output.0, Fp::from(5u64));
    }

    #[test]
    fn test_step_counter_gadget_chain() {
        let gadget = StepCounterGadget::<Fp>::new(Fp::from(10u64));
        let mut env = Trace::<Fp>::new(16);

        // Chain: 0 -> 10 -> 20 -> 30
        let mut current = Fp::from(0u64);

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

        assert_eq!(current, Fp::from(30u64));
    }

    /// Verify that output positions correctly describe where outputs are written in the trace.
    #[test]
    fn test_counter_gadget_output_positions_match_trace() {
        use crate::circuits::gadget::test_utils::verify_trace_positions;

        let gadget = CounterGadget::new();
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
            <CounterGadget as TypedGadget<Fp>>::input_positions(),
            &[input_val],
            "input",
        );

        verify_trace_positions(
            &env,
            current_row,
            <CounterGadget as TypedGadget<Fp>>::output_positions(),
            &[expected_output.0],
            "output",
        );
    }

    /// Verify that output positions correctly describe where outputs are written in the trace.
    #[test]
    fn test_step_counter_gadget_output_positions_match_trace() {
        use crate::circuits::gadget::test_utils::verify_trace_positions;

        let gadget = StepCounterGadget::<Fp>::new(Fp::from(7u64));
        let mut env = Trace::<Fp>::new(16);

        // Input value
        let input_val = Fp::from(10u64);
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
            <StepCounterGadget<Fp> as TypedGadget<Fp>>::input_positions(),
            &[input_val],
            "input",
        );

        verify_trace_positions(
            &env,
            current_row,
            <StepCounterGadget<Fp> as TypedGadget<Fp>>::output_positions(),
            &[expected_output.0],
            "output",
        );
    }
}
