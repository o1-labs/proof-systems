//! Trivial circuit that passes through its input unchanged.

use ark_ff::PrimeField;

use crate::circuit::{CircuitEnv, SelectorEnv, StepCircuit};

/// A trivial circuit that passes through its input unchanged.
///
/// This is useful for testing and as a placeholder secondary circuit.
#[derive(Clone, Debug, Default)]
pub struct TrivialCircuit<F> {
    _marker: std::marker::PhantomData<F>,
}

impl<F: PrimeField> TrivialCircuit<F> {
    /// Create a new trivial circuit.
    pub fn new() -> Self {
        Self {
            _marker: std::marker::PhantomData,
        }
    }
}

impl<F: PrimeField> StepCircuit<F, 1> for TrivialCircuit<F> {
    const NAME: &'static str = "TrivialCircuit";

    fn synthesize<E: CircuitEnv<F> + SelectorEnv<F>>(&self, _env: &mut E, z: &[E::Variable; 1]) -> [E::Variable; 1] {
        [z[0].clone()]
    }

    fn output(&self, z: &[F; 1]) -> [F; 1] {
        *z
    }
}

#[cfg(test)]
mod constraint_tests {
    use super::*;
    use crate::circuit::ConstraintEnv;
    use mina_curves::pasta::Fp;

    #[test]
    fn test_trivial_output() {
        let circuit = TrivialCircuit::<Fp>::new();

        let z0 = [Fp::from(42u64)];
        let z1 = circuit.output(&z0);
        assert_eq!(z1, z0);
    }

    #[test]
    fn test_trivial_constraints() {
        let circuit = TrivialCircuit::<Fp>::new();

        let mut env = ConstraintEnv::<Fp>::new();
        let z = env.make_input_vars::<1>();
        let _ = circuit.synthesize(&mut env, &z);

        // Trivial circuit has no constraints
        assert_eq!(
            env.num_constraints(),
            0,
            "TrivialCircuit should have no constraints"
        );

        // Check all degrees are within MAX_DEGREE (trivially true for 0 constraints)
        env.check_degrees()
            .expect("All constraints should have degree <= MAX_DEGREE");
    }

    /// Regression test for circuit metrics.
    /// If this test fails, the circuit implementation has changed.
    #[test]
    fn test_trivial_metrics() {
        let circuit = TrivialCircuit::<Fp>::new();

        let mut env = ConstraintEnv::<Fp>::new();
        let z = env.make_input_vars::<1>();
        let _ = circuit.synthesize(&mut env, &z);

        assert_eq!(env.num_constraints(), 0, "constraints changed");
        assert_eq!(env.num_witness_allocations(), 0, "witness allocations changed");
        assert_eq!(env.max_degree(), 0, "max degree changed");
    }
}

/// Trace tests for TrivialCircuit.
///
/// This module tests witness generation using the Trace environment.
#[cfg(test)]
mod trace_tests {
    use mina_curves::pasta::Fp;

    use crate::circuit::{StepCircuit, Trace};

    use super::TrivialCircuit;

    #[test]
    fn test_trivial_circuit_trace() {
        let circuit = TrivialCircuit::<Fp>::new();
        let mut env = Trace::<Fp>::new(16);

        let input = Fp::from(42u64);
        let z = env.make_input_vars([input]);
        let output = circuit.synthesize(&mut env, &z);

        // Trivial circuit passes through input unchanged
        assert_eq!(output[0], input);
        assert_eq!(env.get(0, 0), Some(&input));
    }

    #[test]
    fn test_trivial_circuit_chain() {
        let circuit = TrivialCircuit::<Fp>::new();
        let mut env = Trace::<Fp>::new(16);

        // Chain multiple steps - output should always equal initial input
        let initial = Fp::from(123u64);
        let mut current = initial;

        for i in 0..5 {
            if i > 0 {
                env.next_row();
            }
            let z = env.make_input_vars([current]);
            let output = circuit.synthesize(&mut env, &z);
            current = output[0];
        }

        // All values should be the same
        assert_eq!(current, initial);
        for row in 0..5 {
            assert_eq!(env.get(row, 0), Some(&initial));
        }
    }

    #[test]
    fn test_trivial_output_matches() {
        let circuit = TrivialCircuit::<Fp>::new();

        let test_values: Vec<u64> = vec![0, 1, 42, 100, 12345];

        for val in test_values {
            let mut env = Trace::<Fp>::new(16);
            let input = Fp::from(val);
            let z = env.make_input_vars([input]);

            let synth_output = circuit.synthesize(&mut env, &z);
            let direct_output = circuit.output(&[input]);

            assert_eq!(synth_output[0], direct_output[0]);
            assert_eq!(synth_output[0], input);
        }
    }
}
