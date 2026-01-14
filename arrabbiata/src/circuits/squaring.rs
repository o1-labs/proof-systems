//! Squaring circuit: z_{i+1} = z_i^2.

use ark_ff::PrimeField;

use crate::circuit::{CircuitEnv, SelectorEnv, StepCircuit};

/// A circuit that computes squaring: z_{i+1} = z_i^2.
///
/// Each step squares the input once. For multiple squarings,
/// run multiple IVC steps.
#[derive(Clone, Debug, Default)]
pub struct SquaringCircuit<F> {
    _marker: std::marker::PhantomData<F>,
}

impl<F: PrimeField> SquaringCircuit<F> {
    /// Create a new squaring circuit.
    pub fn new() -> Self {
        Self {
            _marker: std::marker::PhantomData,
        }
    }
}

impl<F: PrimeField> StepCircuit<F, 1> for SquaringCircuit<F> {
    const NAME: &'static str = "SquaringCircuit";

    fn synthesize<E: CircuitEnv<F> + SelectorEnv<F>>(&self, env: &mut E, z: &[E::Variable; 1]) -> [E::Variable; 1] {
        let x = z[0].clone();

        // Compute x * x first to get the value (for Trace) or expression (for ConstraintEnv)
        let computed = x.clone() * x;

        // Allocate and write the squared value
        let x_squared = {
            let pos = env.allocate();
            env.write_column(pos, computed.clone())
        };

        // Constrain x_squared = x * x (degree 2)
        env.assert_eq_named("squaring", &x_squared, &computed);

        [x_squared]
    }

    fn output(&self, z: &[F; 1]) -> [F; 1] {
        [z[0] * z[0]]
    }
}

/// A circuit that computes multiple squarings per fold.
///
/// This demonstrates how to amortize folding cost over many iterations.
/// Each fold computes `steps_per_fold` squarings: z -> z^{2^n}.
///
/// # Constraints
///
/// The circuit defines 1 constraint expression (the squaring relation):
/// - x_squared = x * x (degree 2)
///
/// This constraint is applied to `steps_per_fold` rows of the witness.
///
/// # Example
///
/// With `steps_per_fold = 4`:
/// - One fold computes: z -> z^2 -> z^4 -> z^8 -> z^16
/// - Uses 1 constraint expression applied to 4 rows
#[derive(Clone, Debug)]
pub struct RepeatedSquaringCircuit<F: PrimeField> {
    /// Number of squarings (rows) per fold
    pub steps_per_fold: usize,
    _marker: std::marker::PhantomData<F>,
}

impl<F: PrimeField> RepeatedSquaringCircuit<F> {
    /// Create a new repeated squaring circuit.
    ///
    /// # Arguments
    ///
    /// * `steps_per_fold` - Number of squarings per fold. Must be at least 1.
    pub fn new(steps_per_fold: usize) -> Self {
        assert!(steps_per_fold > 0, "Must have at least 1 step per fold");
        Self {
            steps_per_fold,
            _marker: std::marker::PhantomData,
        }
    }
}

impl<F: PrimeField> StepCircuit<F, 1> for RepeatedSquaringCircuit<F> {
    const NAME: &'static str = "RepeatedSquaringCircuit";

    fn synthesize<E: CircuitEnv<F> + SelectorEnv<F>>(&self, env: &mut E, z: &[E::Variable; 1]) -> [E::Variable; 1] {
        // The constraint expression is defined by one squaring step.
        // The `steps_per_fold` parameter determines how many rows use this constraint.
        SquaringCircuit::new().synthesize(env, z)
    }

    fn output(&self, z: &[F; 1]) -> [F; 1] {
        // The output computes the full `steps_per_fold` squarings
        let mut x = z[0];
        for _ in 0..self.steps_per_fold {
            x = x * x;
        }
        [x]
    }

    fn num_rows(&self) -> usize {
        self.steps_per_fold
    }
}

#[cfg(test)]
mod constraint_tests {
    use super::*;
    use crate::circuit::ConstraintEnv;
    use mina_curves::pasta::Fp;

    #[test]
    fn test_squaring_output() {
        let circuit = SquaringCircuit::<Fp>::new();

        // x -> x^2
        let z0 = [Fp::from(2u64)];
        let z1 = circuit.output(&z0);
        assert_eq!(z1, [Fp::from(4u64)]); // 2^2 = 4

        // Chain: 2 -> 4 -> 16 -> 256
        let z2 = circuit.output(&z1);
        assert_eq!(z2, [Fp::from(16u64)]);
        let z3 = circuit.output(&z2);
        assert_eq!(z3, [Fp::from(256u64)]);
    }

    #[test]
    fn test_squaring_constraints() {
        let circuit = SquaringCircuit::<Fp>::new();

        let mut env = ConstraintEnv::<Fp>::new();
        let z = env.make_input_vars::<1>();
        let _ = circuit.synthesize(&mut env, &z);

        // Should have exactly 1 named constraint: x_squared = x * x
        assert_eq!(
            env.num_constraints(),
            1,
            "SquaringCircuit should have exactly 1 constraint"
        );
        assert_eq!(
            env.num_named_constraints(),
            1,
            "SquaringCircuit should have 1 named constraint"
        );

        // The constraint is: x_squared - x * x = 0
        // x_squared is degree 1, x * x is degree 2
        // So the constraint has degree 2
        let degrees = env.constraint_degrees();
        assert_eq!(degrees[0], 2, "Squaring constraint should have degree 2");

        env.check_degrees()
            .expect("All constraints should have degree <= MAX_DEGREE");
    }

    /// Regression test for circuit metrics.
    /// If this test fails, the circuit implementation has changed.
    #[test]
    fn test_squaring_metrics() {
        let circuit = SquaringCircuit::<Fp>::new();

        let mut env = ConstraintEnv::<Fp>::new();
        let z = env.make_input_vars::<1>();
        let _ = circuit.synthesize(&mut env, &z);

        assert_eq!(env.num_constraints(), 1, "constraints changed");
        assert_eq!(env.num_witness_allocations(), 1, "witness allocations changed");
        assert_eq!(env.max_degree(), 2, "max degree changed");
    }

    #[test]
    fn test_repeated_squaring_output() {
        // 4 squarings per fold: x -> x^16
        let circuit = RepeatedSquaringCircuit::<Fp>::new(4);

        let z0 = [Fp::from(2u64)];
        let z1 = circuit.output(&z0);
        // 2^16 = 65536
        assert_eq!(z1, [Fp::from(65536u64)]);
    }

    #[test]
    fn test_repeated_squaring_constraints() {
        // 100 steps per fold - same 1 constraint expression, 100 rows
        let circuit = RepeatedSquaringCircuit::<Fp>::new(100);

        let mut env = ConstraintEnv::<Fp>::new();
        let z = env.make_input_vars::<1>();
        let _ = circuit.synthesize(&mut env, &z);

        // 1 unique named constraint (deduplicated)
        assert_eq!(env.num_constraints(), 1);
        assert_eq!(env.num_named_constraints(), 1);
        assert_eq!(env.max_degree(), 2);
        // The num_rows tells us how many rows use this constraint
        assert_eq!(circuit.num_rows(), 100);
    }

    /// Regression test for RepeatedSquaringCircuit metrics.
    #[test]
    fn test_repeated_squaring_metrics() {
        let circuit = RepeatedSquaringCircuit::<Fp>::new(10_000);

        let mut env = ConstraintEnv::<Fp>::new();
        let z = env.make_input_vars::<1>();
        let _ = circuit.synthesize(&mut env, &z);

        assert_eq!(env.num_constraints(), 1, "constraints changed");
        assert_eq!(env.num_witness_allocations(), 1, "witness allocations changed");
        assert_eq!(env.max_degree(), 2, "max degree changed");
        assert_eq!(circuit.num_rows(), 10_000, "num_rows changed");
    }

    #[test]
    #[should_panic(expected = "Must have at least 1 step per fold")]
    fn test_repeated_squaring_zero_panics() {
        let _ = RepeatedSquaringCircuit::<Fp>::new(0);
    }
}

/// Trace tests for SquaringCircuit.
///
/// This module tests witness generation using the Trace environment.
#[cfg(test)]
mod trace_tests {
    use mina_curves::pasta::Fp;

    use crate::circuit::{StepCircuit, Trace};

    use super::{RepeatedSquaringCircuit, SquaringCircuit};

    #[test]
    fn test_with_squaring_circuit() {
        let circuit = SquaringCircuit::<Fp>::new();
        let mut env = Trace::<Fp>::new(16);

        // Input: 3
        let input_val = Fp::from(3u64);
        let z = env.make_input_vars([input_val]);

        // Run synthesize
        let output = circuit.synthesize(&mut env, &z);

        // Output should be 9 (3^2)
        let expected = circuit.output(&[input_val]);
        assert_eq!(output[0], expected[0]);
        assert_eq!(output[0], Fp::from(9u64));

        // Verify the witness table has the input
        assert_eq!(env.get(0, 0), Some(&Fp::from(3u64)));
    }

    #[test]
    fn test_with_squaring_circuit_chain() {
        let circuit = SquaringCircuit::<Fp>::new();
        let mut env = Trace::<Fp>::new(16);

        // Run 3 steps: 2 -> 4 -> 16 -> 256
        let mut current = Fp::from(2u64);
        for i in 0..3 {
            if i > 0 {
                env.next_row();
            }
            let z = env.make_input_vars([current]);
            let output = circuit.synthesize(&mut env, &z);
            current = output[0];
        }

        // Final value should be 256
        assert_eq!(current, Fp::from(256u64));

        // Verify trace (num_rows is domain_size, not filled rows)
        assert_eq!(env.num_rows(), 16);
        assert_eq!(env.current_row(), 2); // We're on the 3rd row (index 2)
        assert_eq!(env.get(0, 0), Some(&Fp::from(2u64))); // input of step 1
        assert_eq!(env.get(1, 0), Some(&Fp::from(4u64))); // input of step 2
        assert_eq!(env.get(2, 0), Some(&Fp::from(16u64))); // input of step 3
    }

    #[test]
    fn test_squaring_output_matches_for_various_inputs() {
        let circuit = SquaringCircuit::<Fp>::new();

        // Test various input values
        let test_values: Vec<u64> = vec![0, 1, 2, 3, 5, 7, 10, 100, 1000, 12345];

        for val in test_values {
            let mut env = Trace::<Fp>::new(16);
            let input = Fp::from(val);
            let z = env.make_input_vars([input]);

            let synth_output = circuit.synthesize(&mut env, &z);
            let direct_output = circuit.output(&[input]);

            assert_eq!(
                synth_output[0], direct_output[0],
                "synthesize output should match output() for input {}",
                val
            );
            assert_eq!(
                synth_output[0],
                Fp::from(val * val),
                "output should be {} for input {}",
                val * val,
                val
            );
        }
    }

    #[test]
    fn test_squaring_witness_table_structure() {
        let circuit = SquaringCircuit::<Fp>::new();
        let mut env = Trace::<Fp>::new(16);

        // Input: 5
        let input = Fp::from(5u64);
        let z = env.make_input_vars([input]);
        let output = circuit.synthesize(&mut env, &z);

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
        assert_eq!(output[0], Fp::from(25u64), "Output should be 25");
    }

    #[test]
    fn test_squaring_zero_input() {
        let circuit = SquaringCircuit::<Fp>::new();
        let mut env = Trace::<Fp>::new(16);

        // 0^2 = 0
        let z = env.make_input_vars([Fp::from(0u64)]);
        let output = circuit.synthesize(&mut env, &z);

        assert_eq!(output[0], Fp::from(0u64));
        assert_eq!(env.get(0, 0), Some(&Fp::from(0u64)));
        assert_eq!(env.get(0, 1), Some(&Fp::from(0u64)));
    }

    #[test]
    fn test_squaring_one_input() {
        let circuit = SquaringCircuit::<Fp>::new();
        let mut env = Trace::<Fp>::new(16);

        // 1^2 = 1
        let z = env.make_input_vars([Fp::from(1u64)]);
        let output = circuit.synthesize(&mut env, &z);

        assert_eq!(output[0], Fp::from(1u64));
        assert_eq!(env.get(0, 0), Some(&Fp::from(1u64)));
        assert_eq!(env.get(0, 1), Some(&Fp::from(1u64)));
    }

    #[test]
    fn test_squaring_long_chain() {
        let circuit = SquaringCircuit::<Fp>::new();
        let mut env = Trace::<Fp>::new(16);

        // Start with 2, square 8 times: 2 -> 4 -> 16 -> 256 -> 65536 -> ...
        let mut current = Fp::from(2u64);

        for i in 0..8 {
            if i > 0 {
                env.next_row();
            }
            let z = env.make_input_vars([current]);
            let output = circuit.synthesize(&mut env, &z);
            current = output[0];
        }

        // Verify the chain: 2^(2^8) = 2^256
        assert_eq!(env.num_rows(), 16); // domain_size
        assert_eq!(env.current_row(), 7); // We're on the 8th row (index 7)

        // Verify each row's input matches expected
        assert_eq!(env.get(0, 0), Some(&Fp::from(2u64)));
        assert_eq!(env.get(1, 0), Some(&Fp::from(4u64)));
        assert_eq!(env.get(2, 0), Some(&Fp::from(16u64)));
        assert_eq!(env.get(3, 0), Some(&Fp::from(256u64)));
        assert_eq!(env.get(4, 0), Some(&Fp::from(65536u64)));
    }

    #[test]
    fn test_squaring_reset_and_reuse() {
        let circuit = SquaringCircuit::<Fp>::new();
        let mut env = Trace::<Fp>::new(16);

        // First computation
        let z1 = env.make_input_vars([Fp::from(3u64)]);
        let out1 = circuit.synthesize(&mut env, &z1);
        assert_eq!(out1[0], Fp::from(9u64));

        // Reset the environment
        env.reset();

        // Second computation with different input
        let z2 = env.make_input_vars([Fp::from(7u64)]);
        let out2 = circuit.synthesize(&mut env, &z2);
        assert_eq!(out2[0], Fp::from(49u64));

        // Verify reset cleared the old data (but domain_size stays the same)
        assert_eq!(env.num_rows(), 16);
        assert_eq!(env.current_row(), 0);
        assert_eq!(env.get(0, 0), Some(&Fp::from(7u64)));
        assert_eq!(env.get(0, 1), Some(&Fp::from(49u64)));
    }

    #[test]
    fn test_squaring_column_tracking() {
        let circuit = SquaringCircuit::<Fp>::new();
        let mut env = Trace::<Fp>::new(16);

        // Before synthesis
        assert_eq!(env.current_col(), 0);

        // After setting input
        let z = env.make_input_vars([Fp::from(4u64)]);
        assert_eq!(env.current_col(), 1, "After input, col should be 1");

        // After synthesis (which allocates one witness)
        let _ = circuit.synthesize(&mut env, &z);
        assert_eq!(
            env.current_col(),
            2,
            "After synthesis, col should be 2 (input + 1 witness)"
        );
    }

    #[test]
    fn test_repeated_squaring_circuit() {
        let circuit = RepeatedSquaringCircuit::<Fp>::new(4);
        let mut env = Trace::<Fp>::new(16);

        // Input: 2, with 4 squarings per fold = 2^16 = 65536
        let input = Fp::from(2u64);
        let z = env.make_input_vars([input]);

        let synth_output = circuit.synthesize(&mut env, &z);
        let direct_output = circuit.output(&[input]);

        // synthesize only does 1 step, but output computes all steps_per_fold
        // So we compare against one squaring
        assert_eq!(
            synth_output[0],
            Fp::from(4u64),
            "synthesize computes one step"
        );
        assert_eq!(
            direct_output[0],
            Fp::from(65536u64),
            "output computes all 4 steps"
        );
    }
}
