//! Counter circuit - a simple incrementing counter.
//!
//! This is the simplest non-trivial IVC circuit: it just increments a counter
//! each step. Useful as a baseline benchmark.
//!
//! After N iterations: output = input + N

use ark_ff::PrimeField;

use crate::circuit::{CircuitEnv, SelectorEnv, StepCircuit};

/// A simple counter circuit that increments by 1 each step.
#[derive(Clone, Debug)]
pub struct CounterCircuit<F: PrimeField> {
    _marker: std::marker::PhantomData<F>,
}

impl<F: PrimeField> CounterCircuit<F> {
    /// Create a new counter circuit.
    pub fn new() -> Self {
        Self {
            _marker: std::marker::PhantomData,
        }
    }
}

impl<F: PrimeField> Default for CounterCircuit<F> {
    fn default() -> Self {
        Self::new()
    }
}

impl<F: PrimeField> StepCircuit<F, 1> for CounterCircuit<F> {
    const NAME: &'static str = "CounterCircuit";

    fn synthesize<E: CircuitEnv<F> + SelectorEnv<F>>(&self, env: &mut E, z: &[E::Variable; 1]) -> [E::Variable; 1] {
        let counter = z[0].clone();
        let one = env.one();
        let incremented = counter + one;

        // Allocate and write computed value
        let output = {
            let pos = env.allocate();
            env.write_column(pos, incremented.clone())
        };
        env.assert_eq(&output, &incremented);

        [output]
    }

    fn output(&self, z: &[F; 1]) -> [F; 1] {
        [z[0] + F::from(1u64)]
    }
}

/// A counter that increments by a configurable step size.
#[derive(Clone, Debug)]
pub struct StepCounterCircuit<F: PrimeField> {
    step_size: F,
}

impl<F: PrimeField> StepCounterCircuit<F> {
    /// Create a counter that increments by the given step size.
    pub fn new(step_size: F) -> Self {
        Self { step_size }
    }
}

impl<F: PrimeField> StepCircuit<F, 1> for StepCounterCircuit<F> {
    const NAME: &'static str = "StepCounterCircuit";

    fn synthesize<E: CircuitEnv<F> + SelectorEnv<F>>(&self, env: &mut E, z: &[E::Variable; 1]) -> [E::Variable; 1] {
        let counter = z[0].clone();
        let step = env.constant(self.step_size);
        let incremented = counter + step;

        // Allocate and write computed value
        let output = {
            let pos = env.allocate();
            env.write_column(pos, incremented.clone())
        };
        env.assert_eq(&output, &incremented);

        [output]
    }

    fn output(&self, z: &[F; 1]) -> [F; 1] {
        [z[0] + self.step_size]
    }
}

#[cfg(test)]
mod constraint_tests {
    use super::*;
    use crate::circuit::ConstraintEnv;
    use mina_curves::pasta::Fp;
    use rand::{Rng, SeedableRng};

    /// Number of random test iterations
    const NUM_RANDOM_TESTS: usize = 10;

    #[test]
    fn test_counter_output() {
        let circuit = CounterCircuit::<Fp>::new();
        let z = [Fp::from(0u64)];

        let output = circuit.output(&z);
        assert_eq!(output[0], Fp::from(1u64));
    }

    #[test]
    fn test_counter_iterations() {
        let circuit = CounterCircuit::<Fp>::new();
        let mut z = [Fp::from(0u64)];

        for i in 1..=100 {
            z = circuit.output(&z);
            assert_eq!(z[0], Fp::from(i as u64));
        }
    }

    #[test]
    fn test_counter_constraints() {
        let circuit = CounterCircuit::<Fp>::new();

        let mut env = ConstraintEnv::<Fp>::new();
        let z = env.make_input_vars::<1>();
        let _ = circuit.synthesize(&mut env, &z);

        // Counter circuit has 1 constraint: output = input + 1
        assert_eq!(
            env.num_constraints(),
            1,
            "CounterCircuit should have exactly 1 constraint"
        );

        // The constraint is: output - (counter + 1) = 0
        // output is degree 1, counter + 1 is degree 1
        // So the constraint has degree 1
        let degrees = env.constraint_degrees();
        assert_eq!(degrees[0], 1, "Counter constraint should have degree 1");

        env.check_degrees()
            .expect("All constraints should have degree <= MAX_DEGREE");
    }

    /// Regression test for circuit metrics.
    /// If this test fails, the circuit implementation has changed.
    #[test]
    fn test_counter_metrics() {
        let circuit = CounterCircuit::<Fp>::new();

        let mut env = ConstraintEnv::<Fp>::new();
        let z = env.make_input_vars::<1>();
        let _ = circuit.synthesize(&mut env, &z);

        assert_eq!(env.num_constraints(), 1, "constraints changed");
        assert_eq!(env.num_witness_allocations(), 1, "witness allocations changed");
        assert_eq!(env.max_degree(), 1, "max degree changed");
    }

    #[test]
    fn test_step_counter() {
        let circuit = StepCounterCircuit::<Fp>::new(Fp::from(5u64));
        let mut z = [Fp::from(0u64)];

        for i in 1..=10 {
            z = circuit.output(&z);
            assert_eq!(z[0], Fp::from(i * 5));
        }
    }

    #[test]
    fn test_step_counter_constraints() {
        let circuit = StepCounterCircuit::<Fp>::new(Fp::from(5u64));

        let mut env = ConstraintEnv::<Fp>::new();
        let z = env.make_input_vars::<1>();
        let _ = circuit.synthesize(&mut env, &z);

        // StepCounterCircuit has 1 constraint: output = input + step
        assert_eq!(
            env.num_constraints(),
            1,
            "StepCounterCircuit should have exactly 1 constraint"
        );

        assert_eq!(
            env.num_witness_allocations(),
            1,
            "StepCounterCircuit should have 1 witness allocation"
        );

        // The constraint is linear (degree 1)
        let degrees = env.constraint_degrees();
        assert_eq!(degrees[0], 1, "StepCounter constraint should have degree 1");

        env.check_degrees()
            .expect("All constraints should have degree <= MAX_DEGREE");
    }

    /// Regression test for StepCounterCircuit metrics.
    #[test]
    fn test_step_counter_metrics() {
        let circuit = StepCounterCircuit::<Fp>::new(Fp::from(7u64));

        let mut env = ConstraintEnv::<Fp>::new();
        let z = env.make_input_vars::<1>();
        let _ = circuit.synthesize(&mut env, &z);

        assert_eq!(env.num_constraints(), 1, "constraints changed");
        assert_eq!(env.num_witness_allocations(), 1, "witness allocations changed");
        assert_eq!(env.max_degree(), 1, "max degree changed");
    }

    /// Test that CounterCircuit constraint expression is well-formed.
    #[test]
    fn test_counter_constraint_structure() {
        let circuit = CounterCircuit::<Fp>::new();

        let mut env = ConstraintEnv::<Fp>::new();
        let z = env.make_input_vars::<1>();
        let _ = circuit.synthesize(&mut env, &z);

        // Verify constraint count
        assert_eq!(env.num_constraints(), 1);

        // Verify the constraint structure: there should be exactly one constraint
        let constraints = env.constraints();
        assert_eq!(constraints.len(), 1);

        // The constraint should have degree 1 (linear)
        let degrees = env.constraint_degrees();
        assert_eq!(degrees.len(), 1);
        assert_eq!(degrees[0], 1, "Counter constraint should be linear (degree 1)");
    }

    /// Test CounterCircuit with random starting values.
    #[test]
    fn test_counter_various_starting_values() {
        let circuit = CounterCircuit::<Fp>::new();
        let mut rng = rand::rngs::StdRng::seed_from_u64(42);

        for _ in 0..NUM_RANDOM_TESTS {
            let val: u64 = rng.gen();
            let z = [Fp::from(val)];
            let output = circuit.output(&z);
            assert_eq!(output[0], Fp::from(val) + Fp::from(1u64));
        }
    }

    /// Test StepCounterCircuit with random step sizes.
    #[test]
    fn test_step_counter_various_steps() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(42);

        for _ in 0..NUM_RANDOM_TESTS {
            // Generate random non-zero step size
            let step: u64 = rng.gen_range(1..1_000_000);
            let circuit = StepCounterCircuit::<Fp>::new(Fp::from(step));

            // Test output with random starting value
            let start: u64 = rng.gen();
            let z = [Fp::from(start)];
            let output = circuit.output(&z);
            assert_eq!(output[0], Fp::from(start) + Fp::from(step));

            // Test constraints - StepCounterCircuit has 1 constraint with degree 1
            let mut env = ConstraintEnv::<Fp>::new();
            let z_vars = env.make_input_vars::<1>();
            let _ = circuit.synthesize(&mut env, &z_vars);

            assert_eq!(
                env.num_constraints(),
                1,
                "StepCounterCircuit should have 1 constraint for step size {}",
                step
            );
            assert_eq!(
                env.max_degree(),
                1,
                "StepCounterCircuit should have max degree 1 for step size {}",
                step
            );
        }
    }

    /// Test that CounterCircuit and StepCounterCircuit(1) produce same results.
    #[test]
    fn test_counter_equivalence() {
        let counter = CounterCircuit::<Fp>::new();
        let step_counter = StepCounterCircuit::<Fp>::new(Fp::from(1u64));

        let mut z1 = [Fp::from(0u64)];
        let mut z2 = [Fp::from(0u64)];

        for _ in 0..10 {
            z1 = counter.output(&z1);
            z2 = step_counter.output(&z2);
            assert_eq!(z1[0], z2[0], "CounterCircuit and StepCounterCircuit(1) should match");
        }
    }
}

/// Trace tests for CounterCircuit.
///
/// This module tests witness generation using the Trace environment.
#[cfg(test)]
mod trace_tests {
    use mina_curves::pasta::Fp;

    use crate::circuit::{StepCircuit, Trace};

    use super::{CounterCircuit, StepCounterCircuit};

    #[test]
    fn test_counter_circuit_trace() {
        let circuit = CounterCircuit::<Fp>::new();
        let mut env = Trace::<Fp>::new(16);

        let input = Fp::from(0u64);
        let z = env.make_input_vars([input]);
        let output = circuit.synthesize(&mut env, &z);

        // Output should be input + 1
        assert_eq!(output[0], Fp::from(1u64));
        assert_eq!(env.get(0, 0), Some(&Fp::from(0u64)));
    }

    #[test]
    fn test_counter_circuit_chain() {
        let circuit = CounterCircuit::<Fp>::new();
        let mut env = Trace::<Fp>::new(16);

        // Chain multiple steps: 0 -> 1 -> 2 -> 3 -> 4 -> 5
        let mut current = Fp::from(0u64);

        for i in 0..5 {
            if i > 0 {
                env.next_row();
            }
            let z = env.make_input_vars([current]);
            let output = circuit.synthesize(&mut env, &z);
            current = output[0];
        }

        // Final value should be 5
        assert_eq!(current, Fp::from(5u64));

        // Verify trace
        for row in 0..5 {
            assert_eq!(env.get(row, 0), Some(&Fp::from(row as u64)));
        }
    }

    #[test]
    fn test_counter_output_matches() {
        let circuit = CounterCircuit::<Fp>::new();

        let test_values: Vec<u64> = vec![0, 1, 42, 100, 12345];

        for val in test_values {
            let mut env = Trace::<Fp>::new(16);
            let input = Fp::from(val);
            let z = env.make_input_vars([input]);

            let synth_output = circuit.synthesize(&mut env, &z);
            let direct_output = circuit.output(&[input]);

            assert_eq!(synth_output[0], direct_output[0]);
            assert_eq!(synth_output[0], Fp::from(val + 1));
        }
    }

    #[test]
    fn test_step_counter_trace() {
        let circuit = StepCounterCircuit::<Fp>::new(Fp::from(5u64));
        let mut env = Trace::<Fp>::new(16);

        let input = Fp::from(0u64);
        let z = env.make_input_vars([input]);
        let output = circuit.synthesize(&mut env, &z);

        // Output should be input + 5
        assert_eq!(output[0], Fp::from(5u64));
    }

    #[test]
    fn test_step_counter_chain() {
        let circuit = StepCounterCircuit::<Fp>::new(Fp::from(10u64));
        let mut env = Trace::<Fp>::new(16);

        // Chain: 0 -> 10 -> 20 -> 30
        let mut current = Fp::from(0u64);

        for i in 0..3 {
            if i > 0 {
                env.next_row();
            }
            let z = env.make_input_vars([current]);
            let output = circuit.synthesize(&mut env, &z);
            current = output[0];
        }

        assert_eq!(current, Fp::from(30u64));
    }
}
