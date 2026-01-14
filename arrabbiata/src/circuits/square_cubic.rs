//! Square-Cubic composite circuit demonstrating circuit composition.
//!
//! This circuit chains SquaringCircuit and CubicCircuit by reusing
//! their existing implementations.

use ark_ff::PrimeField;

use crate::circuit::{CircuitEnv, SelectorEnv, StepCircuit};
use crate::circuits::{CubicCircuit, SquaringCircuit};

/// A circuit that composes SquaringCircuit and CubicCircuit.
///
/// Computes: x -> x^2 -> (x^2)^3 + x^2 + 5 = x^6 + x^2 + 5
///
/// This demonstrates how to chain existing circuits by calling
/// their `synthesize` methods in sequence.
#[derive(Clone, Debug, Default)]
pub struct SquareCubicCircuit<F> {
    _marker: std::marker::PhantomData<F>,
}

impl<F: PrimeField> SquareCubicCircuit<F> {
    pub fn new() -> Self {
        Self {
            _marker: std::marker::PhantomData,
        }
    }
}

impl<F: PrimeField> StepCircuit<F, 1> for SquareCubicCircuit<F> {
    const NAME: &'static str = "SquareCubicCircuit";

    fn synthesize<E: CircuitEnv<F> + SelectorEnv<F>>(&self, env: &mut E, z: &[E::Variable; 1]) -> [E::Variable; 1] {
        // Chain: input -> SquaringCircuit -> CubicCircuit -> output
        let squared = SquaringCircuit::new().synthesize(env, z);
        CubicCircuit::new().synthesize(env, &squared)
    }

    fn output(&self, z: &[F; 1]) -> [F; 1] {
        let squared = SquaringCircuit::new().output(z);
        CubicCircuit::new().output(&squared)
    }
}

#[cfg(test)]
mod constraint_tests {
    use super::*;
    use crate::circuit::ConstraintEnv;
    use mina_curves::pasta::Fp;

    #[test]
    fn test_square_cubic_output() {
        let circuit = SquareCubicCircuit::<Fp>::new();

        // x=2: x^2=4, then 4^3 + 4 + 5 = 64 + 4 + 5 = 73
        let z0 = [Fp::from(2u64)];
        let z1 = circuit.output(&z0);
        assert_eq!(z1, [Fp::from(73u64)]);

        // x=3: x^2=9, then 9^3 + 9 + 5 = 729 + 9 + 5 = 743
        let z0 = [Fp::from(3u64)];
        let z1 = circuit.output(&z0);
        assert_eq!(z1, [Fp::from(743u64)]);
    }

    #[test]
    fn test_square_cubic_constraints() {
        let circuit = SquareCubicCircuit::<Fp>::new();

        let mut env = ConstraintEnv::<Fp>::new();
        let z = env.make_input_vars::<1>();
        let _ = circuit.synthesize(&mut env, &z);

        // SquaringCircuit: 1 constraint (degree 2)
        // CubicCircuit: 1 constraint (degree 3)
        // Total: 2 constraints
        assert_eq!(env.num_constraints(), 2, "Should have 2 constraints");
        assert_eq!(env.max_degree(), 3, "Max degree should be 3 from cubic");
    }

    /// Regression test for circuit metrics.
    #[test]
    fn test_square_cubic_metrics() {
        let circuit = SquareCubicCircuit::<Fp>::new();

        let mut env = ConstraintEnv::<Fp>::new();
        let z = env.make_input_vars::<1>();
        let _ = circuit.synthesize(&mut env, &z);

        assert_eq!(env.num_constraints(), 2, "constraints changed");
        assert_eq!(env.num_witness_allocations(), 2, "witness allocations changed");
        assert_eq!(env.max_degree(), 3, "max degree changed");
    }
}

/// Trace tests for SquareCubicCircuit.
///
/// This module tests witness generation using the Trace environment.
#[cfg(test)]
mod trace_tests {
    use mina_curves::pasta::Fp;

    use crate::circuit::{StepCircuit, Trace};

    use super::SquareCubicCircuit;

    #[test]
    fn test_with_square_cubic_circuit() {
        let circuit = SquareCubicCircuit::<Fp>::new();
        let mut env = Trace::<Fp>::new(16);

        // Input: 2
        // x^2 = 4, then 4^3 + 4 + 5 = 64 + 4 + 5 = 73
        let input_val = Fp::from(2u64);
        let z = env.make_input_vars([input_val]);

        let output = circuit.synthesize(&mut env, &z);

        let expected = circuit.output(&[input_val]);
        assert_eq!(output[0], expected[0]);
        assert_eq!(output[0], Fp::from(73u64));
    }

    #[test]
    fn test_square_cubic_chain() {
        let circuit = SquareCubicCircuit::<Fp>::new();
        let mut env = Trace::<Fp>::new(16);

        // Run 3 steps chained
        let mut current = Fp::from(2u64);
        for i in 0..3 {
            if i > 0 {
                env.next_row();
            }
            let z = env.make_input_vars([current]);
            let output = circuit.synthesize(&mut env, &z);
            current = output[0];
        }

        // Step 1: 2 -> 73
        // Step 2: 73 -> 73^2 = 5329, then 5329^3 + 5329 + 5 = 151334226288 + 5329 + 5 = 151334231622
        // Step 3: ... (large number)

        // Just verify we're on row 2 and the chain executed
        assert_eq!(env.current_row(), 2);
        assert_eq!(env.get(0, 0), Some(&Fp::from(2u64))); // First input
        assert_eq!(env.get(1, 0), Some(&Fp::from(73u64))); // Second input (output of first)
    }

    #[test]
    fn test_square_cubic_output_matches_for_various_inputs() {
        let circuit = SquareCubicCircuit::<Fp>::new();

        let test_values: Vec<u64> = vec![0, 1, 2, 3, 5, 7, 10];

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

            // Verify: x^6 + x^2 + 5
            let x2 = val * val;
            let x6 = x2 * x2 * x2;
            let expected = x6 + x2 + 5;
            assert_eq!(
                synth_output[0],
                Fp::from(expected),
                "output should be {} for input {}",
                expected,
                val
            );
        }
    }

    #[test]
    fn test_square_cubic_witness_table_structure() {
        let circuit = SquareCubicCircuit::<Fp>::new();
        let mut env = Trace::<Fp>::new(16);

        // Input: 3
        // x^2 = 9
        // x^6 + x^2 + 5 = 729 + 9 + 5 = 743
        let input = Fp::from(3u64);
        let z = env.make_input_vars([input]);
        let output = circuit.synthesize(&mut env, &z);

        // Check witness table structure:
        // Column 0: input (3)
        // Column 1: x_squared from SquaringCircuit (9)
        // Column 2: cubic result from CubicCircuit (743)
        assert_eq!(
            env.get(0, 0),
            Some(&Fp::from(3u64)),
            "Column 0 should have input"
        );
        assert_eq!(
            env.get(0, 1),
            Some(&Fp::from(9u64)),
            "Column 1 should have x_squared"
        );
        assert_eq!(
            env.get(0, 2),
            Some(&Fp::from(743u64)),
            "Column 2 should have cubic result"
        );
        assert_eq!(output[0], Fp::from(743u64), "Output should be 743");
    }

    #[test]
    fn test_square_cubic_zero_input() {
        let circuit = SquareCubicCircuit::<Fp>::new();
        let mut env = Trace::<Fp>::new(16);

        // 0^2 = 0, 0^3 + 0 + 5 = 5
        let z = env.make_input_vars([Fp::from(0u64)]);
        let output = circuit.synthesize(&mut env, &z);

        assert_eq!(output[0], Fp::from(5u64));
        assert_eq!(env.get(0, 0), Some(&Fp::from(0u64))); // input
        assert_eq!(env.get(0, 1), Some(&Fp::from(0u64))); // x^2
        assert_eq!(env.get(0, 2), Some(&Fp::from(5u64))); // result
    }

    #[test]
    fn test_square_cubic_one_input() {
        let circuit = SquareCubicCircuit::<Fp>::new();
        let mut env = Trace::<Fp>::new(16);

        // 1^2 = 1, 1^3 + 1 + 5 = 7
        let z = env.make_input_vars([Fp::from(1u64)]);
        let output = circuit.synthesize(&mut env, &z);

        assert_eq!(output[0], Fp::from(7u64));
        assert_eq!(env.get(0, 0), Some(&Fp::from(1u64))); // input
        assert_eq!(env.get(0, 1), Some(&Fp::from(1u64))); // x^2
        assert_eq!(env.get(0, 2), Some(&Fp::from(7u64))); // result
    }

    #[test]
    fn test_square_cubic_reset_and_reuse() {
        let circuit = SquareCubicCircuit::<Fp>::new();
        let mut env = Trace::<Fp>::new(16);

        // First computation
        let z1 = env.make_input_vars([Fp::from(2u64)]);
        let out1 = circuit.synthesize(&mut env, &z1);
        assert_eq!(out1[0], Fp::from(73u64));

        // Reset the environment
        env.reset();

        // Second computation with different input
        let z2 = env.make_input_vars([Fp::from(3u64)]);
        let out2 = circuit.synthesize(&mut env, &z2);
        assert_eq!(out2[0], Fp::from(743u64));

        // Verify reset cleared the old data
        assert_eq!(env.current_row(), 0);
        assert_eq!(env.get(0, 0), Some(&Fp::from(3u64)));
    }

    #[test]
    fn test_square_cubic_column_tracking() {
        let circuit = SquareCubicCircuit::<Fp>::new();
        let mut env = Trace::<Fp>::new(16);

        // Before synthesis
        assert_eq!(env.current_col(), 0);

        // After setting input
        let z = env.make_input_vars([Fp::from(4u64)]);
        assert_eq!(env.current_col(), 1, "After input, col should be 1");

        // After synthesis (which allocates 2 witnesses: x^2 and cubic result)
        let _ = circuit.synthesize(&mut env, &z);
        assert_eq!(
            env.current_col(),
            3,
            "After synthesis, col should be 3 (input + 2 witnesses)"
        );
    }
}
