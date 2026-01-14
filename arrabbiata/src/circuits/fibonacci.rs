//! Fibonacci circuit for computing the Fibonacci sequence.

use ark_ff::PrimeField;

use crate::circuit::{CircuitEnv, SelectorEnv, StepCircuit};

/// A circuit for computing the Fibonacci sequence: (x, y) -> (y, x + y).
///
/// This is a classic example for IVC - computing many Fibonacci iterations
/// can be proven in constant verification time.
#[derive(Clone, Debug, Default)]
pub struct FibonacciCircuit<F> {
    _marker: std::marker::PhantomData<F>,
}

impl<F: PrimeField> FibonacciCircuit<F> {
    /// Create a new Fibonacci circuit.
    pub fn new() -> Self {
        Self {
            _marker: std::marker::PhantomData,
        }
    }
}

impl<F: PrimeField> StepCircuit<F, 2> for FibonacciCircuit<F> {
    const NAME: &'static str = "FibonacciCircuit";

    fn synthesize<E: CircuitEnv<F> + SelectorEnv<F>>(&self, env: &mut E, z: &[E::Variable; 2]) -> [E::Variable; 2] {
        let x = z[0].clone();
        let y = z[1].clone();

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

        [out0, out1]
    }

    fn output(&self, z: &[F; 2]) -> [F; 2] {
        [z[1], z[0] + z[1]]
    }
}

/// A circuit that computes multiple Fibonacci steps per fold.
///
/// This demonstrates how to amortize folding cost over many iterations.
/// Each fold computes `steps_per_fold` Fibonacci iterations.
///
/// # Constraints
///
/// The circuit defines 2 constraint expressions (the Fibonacci relation):
/// - out0 = y
/// - out1 = x + y
///
/// These same constraints are applied to `steps_per_fold` rows of the witness.
/// The constraint count is 2 (not 2 * steps_per_fold) because it's the same
/// relation repeated across rows.
///
/// # Example
///
/// With `steps_per_fold = 10_000`:
/// - One fold computes 10,000 Fibonacci steps
/// - Uses 2 constraint expressions applied to 10,000 rows
/// - After N folds: computed N * 10,000 Fibonacci iterations
#[derive(Clone, Debug)]
pub struct RepeatedFibonacciCircuit<F: PrimeField> {
    /// Number of Fibonacci steps (rows) per fold
    pub steps_per_fold: usize,
    _marker: std::marker::PhantomData<F>,
}

impl<F: PrimeField> RepeatedFibonacciCircuit<F> {
    /// Create a new repeated Fibonacci circuit.
    ///
    /// # Arguments
    ///
    /// * `steps_per_fold` - Number of Fibonacci steps per fold. Must be at least 1.
    pub fn new(steps_per_fold: usize) -> Self {
        assert!(steps_per_fold > 0, "Must have at least 1 step per fold");
        Self {
            steps_per_fold,
            _marker: std::marker::PhantomData,
        }
    }
}

impl<F: PrimeField> StepCircuit<F, 2> for RepeatedFibonacciCircuit<F> {
    const NAME: &'static str = "RepeatedFibonacciCircuit";

    fn synthesize<E: CircuitEnv<F> + SelectorEnv<F>>(&self, env: &mut E, z: &[E::Variable; 2]) -> [E::Variable; 2] {
        // The constraint expressions are defined by one Fibonacci step.
        // The `steps_per_fold` parameter determines how many rows of the
        // witness table satisfy these constraints, but the expressions themselves
        // are the same for all rows.
        FibonacciCircuit::new().synthesize(env, z)
    }

    fn output(&self, z: &[F; 2]) -> [F; 2] {
        // The output computes the full `steps_per_fold` iterations
        let mut state = *z;
        for _ in 0..self.steps_per_fold {
            state = FibonacciCircuit::new().output(&state);
        }
        state
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
    fn test_fibonacci_output() {
        let circuit = FibonacciCircuit::<Fp>::new();

        // Fibonacci: 0, 1, 1, 2, 3, 5, 8, 13, 21, 34, ...
        let z0 = [Fp::from(0u64), Fp::from(1u64)];
        let z1 = circuit.output(&z0);
        assert_eq!(z1, [Fp::from(1u64), Fp::from(1u64)]);

        let z2 = circuit.output(&z1);
        assert_eq!(z2, [Fp::from(1u64), Fp::from(2u64)]);

        let z3 = circuit.output(&z2);
        assert_eq!(z3, [Fp::from(2u64), Fp::from(3u64)]);

        let z4 = circuit.output(&z3);
        assert_eq!(z4, [Fp::from(3u64), Fp::from(5u64)]);
    }

    #[test]
    fn test_fibonacci_constraints() {
        let circuit = FibonacciCircuit::<Fp>::new();

        let mut env = ConstraintEnv::<Fp>::new();
        let z = env.make_input_vars::<2>();
        let _ = circuit.synthesize(&mut env, &z);

        // 2 named constraints: fib_out0 = y, fib_out1 = x + y
        assert_eq!(
            env.num_constraints(),
            2,
            "FibonacciCircuit should have 2 constraints"
        );
        assert_eq!(
            env.num_named_constraints(),
            2,
            "FibonacciCircuit should have 2 named constraints"
        );

        // Both constraints have degree 1
        for (i, deg) in env.constraint_degrees().iter().enumerate() {
            assert_eq!(*deg, 1, "Constraint {} should have degree 1", i);
        }

        env.check_degrees()
            .expect("All constraints should have degree <= MAX_DEGREE");
    }

    /// Regression test for circuit metrics.
    /// If this test fails, the circuit implementation has changed.
    #[test]
    fn test_fibonacci_metrics() {
        let circuit = FibonacciCircuit::<Fp>::new();

        let mut env = ConstraintEnv::<Fp>::new();
        let z = env.make_input_vars::<2>();
        let _ = circuit.synthesize(&mut env, &z);

        assert_eq!(env.num_constraints(), 2, "constraints changed");
        assert_eq!(env.num_witness_allocations(), 2, "witness allocations changed");
        assert_eq!(env.max_degree(), 1, "max degree changed");
    }

    #[test]
    fn test_repeated_fibonacci_output() {
        // 5 steps per fold
        let circuit = RepeatedFibonacciCircuit::<Fp>::new(5);

        // Fibonacci: 0, 1, 1, 2, 3, 5, 8, 13, 21, 34, ...
        // After 5 steps from (0, 1): (5, 8)
        let z0 = [Fp::from(0u64), Fp::from(1u64)];
        let z1 = circuit.output(&z0);
        assert_eq!(z1, [Fp::from(5u64), Fp::from(8u64)]);

        // After another 5 steps from (5, 8): (55, 89)
        let z2 = circuit.output(&z1);
        assert_eq!(z2, [Fp::from(55u64), Fp::from(89u64)]);
    }

    #[test]
    fn test_repeated_fibonacci_constraints() {
        // 100 steps per fold - same 2 constraint expressions, 100 rows
        let circuit = RepeatedFibonacciCircuit::<Fp>::new(100);

        let mut env = ConstraintEnv::<Fp>::new();
        let z = env.make_input_vars::<2>();
        let _ = circuit.synthesize(&mut env, &z);

        // 2 unique named constraints (deduplicated)
        assert_eq!(env.num_constraints(), 2);
        assert_eq!(env.num_named_constraints(), 2);
        // But witness is allocated once per call (not deduplicated)
        assert_eq!(env.num_witness_allocations(), 2);
        assert_eq!(env.max_degree(), 1);
        // The num_rows tells us how many rows use these constraints
        assert_eq!(circuit.num_rows(), 100);
    }

    /// Test 10,000 Fibonacci steps in one fold.
    #[test]
    fn test_repeated_fibonacci_10000_steps() {
        let circuit = RepeatedFibonacciCircuit::<Fp>::new(10_000);

        let mut env = ConstraintEnv::<Fp>::new();
        let z = env.make_input_vars::<2>();
        let _ = circuit.synthesize(&mut env, &z);

        // 2 unique constraint expressions (deduplicated by name)
        assert_eq!(env.num_constraints(), 2);
        assert_eq!(env.num_named_constraints(), 2);
        assert_eq!(env.max_degree(), 1);
        // The num_rows tells us how many rows use these constraints
        assert_eq!(circuit.num_rows(), 10_000);
    }

    /// Regression test for RepeatedFibonacciCircuit metrics.
    #[test]
    fn test_repeated_fibonacci_metrics() {
        let circuit = RepeatedFibonacciCircuit::<Fp>::new(10_000);

        let mut env = ConstraintEnv::<Fp>::new();
        let z = env.make_input_vars::<2>();
        let _ = circuit.synthesize(&mut env, &z);

        assert_eq!(env.num_constraints(), 2, "constraints changed");
        assert_eq!(env.num_witness_allocations(), 2, "witness allocations changed");
        assert_eq!(env.max_degree(), 1, "max degree changed");
        assert_eq!(circuit.num_rows(), 10_000, "num_rows changed");
    }

    #[test]
    #[should_panic(expected = "Must have at least 1 step per fold")]
    fn test_repeated_fibonacci_zero_panics() {
        let _ = RepeatedFibonacciCircuit::<Fp>::new(0);
    }
}

/// Trace tests for FibonacciCircuit.
///
/// This module tests witness generation using the Trace environment.
#[cfg(test)]
mod trace_tests {
    use mina_curves::pasta::Fp;

    use crate::circuit::{StepCircuit, Trace};

    use super::{FibonacciCircuit, RepeatedFibonacciCircuit};

    #[test]
    fn test_fibonacci_circuit_trace() {
        let circuit = FibonacciCircuit::<Fp>::new();
        let mut env = Trace::<Fp>::new(16);

        // Fibonacci: (0, 1) -> (1, 1)
        let z = env.make_input_vars([Fp::from(0u64), Fp::from(1u64)]);
        let output = circuit.synthesize(&mut env, &z);

        assert_eq!(output[0], Fp::from(1u64));
        assert_eq!(output[1], Fp::from(1u64));
    }

    #[test]
    fn test_fibonacci_circuit_chain() {
        let circuit = FibonacciCircuit::<Fp>::new();
        let mut env = Trace::<Fp>::new(16);

        // Chain: (0, 1) -> (1, 1) -> (1, 2) -> (2, 3) -> (3, 5) -> (5, 8)
        let mut current = [Fp::from(0u64), Fp::from(1u64)];

        for i in 0..5 {
            if i > 0 {
                env.next_row();
            }
            let z = env.make_input_vars(current);
            let output = circuit.synthesize(&mut env, &z);
            current = [output[0], output[1]];
        }

        // Final: F(5) = 5, F(6) = 8
        assert_eq!(current[0], Fp::from(5u64));
        assert_eq!(current[1], Fp::from(8u64));
    }

    #[test]
    fn test_fibonacci_output_matches() {
        let circuit = FibonacciCircuit::<Fp>::new();

        // Test various starting pairs
        let test_pairs: Vec<(u64, u64)> = vec![(0, 1), (1, 1), (1, 2), (3, 5), (8, 13)];

        for (a, b) in test_pairs {
            let mut env = Trace::<Fp>::new(16);
            let input = [Fp::from(a), Fp::from(b)];
            let z = env.make_input_vars(input);

            let synth_output = circuit.synthesize(&mut env, &z);
            let direct_output = circuit.output(&input);

            assert_eq!(synth_output[0], direct_output[0]);
            assert_eq!(synth_output[1], direct_output[1]);
            // Fibonacci: (a, b) -> (b, a + b)
            assert_eq!(synth_output[0], Fp::from(b));
            assert_eq!(synth_output[1], Fp::from(a + b));
        }
    }

    #[test]
    fn test_fibonacci_witness_structure() {
        let circuit = FibonacciCircuit::<Fp>::new();
        let mut env = Trace::<Fp>::new(16);

        // (3, 5) -> (5, 8)
        let z = env.make_input_vars([Fp::from(3u64), Fp::from(5u64)]);
        let output = circuit.synthesize(&mut env, &z);

        // Check witness structure:
        // Column 0: input x (3)
        // Column 1: input y (5)
        // Column 2: out0 = y (5)
        // Column 3: out1 = x + y (8)
        assert_eq!(env.get(0, 0), Some(&Fp::from(3u64)));
        assert_eq!(env.get(0, 1), Some(&Fp::from(5u64)));
        assert_eq!(env.get(0, 2), Some(&Fp::from(5u64)));
        assert_eq!(env.get(0, 3), Some(&Fp::from(8u64)));
        assert_eq!(output[0], Fp::from(5u64));
        assert_eq!(output[1], Fp::from(8u64));
    }

    #[test]
    fn test_repeated_fibonacci_trace() {
        let circuit = RepeatedFibonacciCircuit::<Fp>::new(5);
        let mut env = Trace::<Fp>::new(16);

        // With 5 steps: (0, 1) -> (5, 8)
        let z = env.make_input_vars([Fp::from(0u64), Fp::from(1u64)]);

        // synthesize does one step, output does 5 steps
        let synth_output = circuit.synthesize(&mut env, &z);
        let direct_output = circuit.output(&[Fp::from(0u64), Fp::from(1u64)]);

        // Synth does 1 step: (0, 1) -> (1, 1)
        assert_eq!(synth_output[0], Fp::from(1u64));
        assert_eq!(synth_output[1], Fp::from(1u64));

        // Output does 5 steps: (0, 1) -> (5, 8)
        assert_eq!(direct_output[0], Fp::from(5u64));
        assert_eq!(direct_output[1], Fp::from(8u64));
    }
}
