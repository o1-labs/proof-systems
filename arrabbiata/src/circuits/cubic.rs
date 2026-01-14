//! Cubic polynomial circuit.

use ark_ff::PrimeField;

use crate::circuit::{CircuitEnv, SelectorEnv, StepCircuit};

/// A circuit for computing the cubic polynomial: x -> x^3 + x + 5.
///
/// This is from the Nova test suite and useful for comparison.
#[derive(Clone, Debug, Default)]
pub struct CubicCircuit<F> {
    _marker: std::marker::PhantomData<F>,
}

impl<F: PrimeField> CubicCircuit<F> {
    /// Create a new cubic circuit.
    pub fn new() -> Self {
        Self {
            _marker: std::marker::PhantomData,
        }
    }
}

impl<F: PrimeField> StepCircuit<F, 1> for CubicCircuit<F> {
    const NAME: &'static str = "CubicCircuit";

    fn synthesize<E: CircuitEnv<F> + SelectorEnv<F>>(&self, env: &mut E, z: &[E::Variable; 1]) -> [E::Variable; 1] {
        let x = z[0].clone();

        // Compute x^3 + x + 5
        let x_sq = x.clone() * x.clone();
        let x_cu = x_sq * x.clone();
        let five = env.constant(F::from(5u64));
        let computed = x_cu + x + five;

        // Allocate and write computed value
        let output = {
            let pos = env.allocate();
            env.write_column(pos, computed.clone())
        };
        env.assert_eq(&output, &computed); // degree 3 (from x^3)

        [output]
    }

    fn output(&self, z: &[F; 1]) -> [F; 1] {
        let x = z[0];
        [x * x * x + x + F::from(5u64)]
    }
}

#[cfg(test)]
mod constraint_tests {
    use super::*;
    use crate::circuit::ConstraintEnv;
    use mina_curves::pasta::Fp;

    #[test]
    fn test_cubic_output() {
        let circuit = CubicCircuit::<Fp>::new();

        // y = x^3 + x + 5
        // x=0: y = 0 + 0 + 5 = 5
        let z0 = [Fp::from(0u64)];
        let z1 = circuit.output(&z0);
        assert_eq!(z1, [Fp::from(5u64)]);

        // x=5: y = 125 + 5 + 5 = 135
        let z2 = circuit.output(&z1);
        assert_eq!(z2, [Fp::from(135u64)]);
    }

    #[test]
    fn test_cubic_constraints() {
        let circuit = CubicCircuit::<Fp>::new();

        let mut env = ConstraintEnv::<Fp>::new();
        let z = env.make_input_vars::<1>();
        let _ = circuit.synthesize(&mut env, &z);

        // CubicCircuit has 1 constraint: output = x^3 + x + 5
        assert_eq!(
            env.num_constraints(),
            1,
            "CubicCircuit should have 1 constraint"
        );

        // The constraint has degree 3 (from x^3)
        let degrees = env.constraint_degrees();
        assert_eq!(degrees[0], 3, "Cubic constraint should have degree 3");

        env.check_degrees()
            .expect("All constraints should have degree <= MAX_DEGREE");
    }

    /// Regression test for circuit metrics.
    /// If this test fails, the circuit implementation has changed.
    #[test]
    fn test_cubic_metrics() {
        let circuit = CubicCircuit::<Fp>::new();

        let mut env = ConstraintEnv::<Fp>::new();
        let z = env.make_input_vars::<1>();
        let _ = circuit.synthesize(&mut env, &z);

        assert_eq!(env.num_constraints(), 1, "constraints changed");
        assert_eq!(env.num_witness_allocations(), 1, "witness allocations changed");
        assert_eq!(env.max_degree(), 3, "max degree changed");
    }
}
