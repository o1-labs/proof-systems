//! MinRoot circuit - a verifiable delay function.

use ark_ff::{BigInteger, PrimeField};
use num_bigint::BigUint;

use crate::circuit::{CircuitEnv, SelectorEnv, StepCircuit};

/// MinRoot circuit - computes the 5th root iteratively.
///
/// This is a verifiable delay function (VDF) based on computing
/// `x_{i+1} = (x_i + y_i)^{1/5}` and `y_{i+1} = x_i`.
///
/// The 5th root is computed as non-deterministic advice and verified
/// by checking `x_{i+1}^5 = x_i + y_i`.
#[derive(Clone, Debug)]
pub struct MinRootCircuit<F: PrimeField> {
    /// Non-deterministic advice: the 5th root values
    pub advice: Vec<MinRootIteration<F>>,
}

/// A single iteration of MinRoot computation.
#[derive(Clone, Debug)]
pub struct MinRootIteration<F: PrimeField> {
    /// Current x value
    pub x_i: F,
    /// Current y value
    pub y_i: F,
    /// Next x value (5th root of x_i + y_i)
    pub x_i_plus_1: F,
    /// Next y value (equals x_i)
    pub y_i_plus_1: F,
}

impl<F: PrimeField> MinRootCircuit<F> {
    /// Create a new MinRoot circuit with precomputed advice.
    ///
    /// # Arguments
    ///
    /// * `num_iters` - Number of MinRoot iterations per step
    /// * `x_0` - Initial x value
    /// * `y_0` - Initial y value
    ///
    /// # Returns
    ///
    /// A tuple of (initial z0 array, circuit with advice)
    pub fn new(num_iters: usize, x_0: F, y_0: F) -> ([F; 2], Self) {
        // Helper to convert ark BigInteger to BigUint
        fn bigint_to_biguint<B: BigInteger>(bigint: &B) -> BigUint {
            let bytes: Vec<u8> = bigint
                .as_ref()
                .iter()
                .flat_map(|limb| limb.to_le_bytes())
                .collect();
            BigUint::from_bytes_le(&bytes)
        }

        // Compute exp = (p - 3) / 5 for 5th root calculation
        // x^exp mod p gives the 5th root
        let modulus = F::MODULUS;
        let p = bigint_to_biguint(&modulus);
        let two = BigUint::from(2u64);
        let three = BigUint::from(3u64);
        let five = BigUint::from(5u64);
        let five_inv = five.modpow(&(&p - &two), &p);
        let exp = (&five_inv * (&p - &three)) % &p;

        let mut advice = Vec::with_capacity(num_iters);
        let mut x_i = x_0;
        let mut y_i = y_0;

        for _ in 0..num_iters {
            // x_{i+1} = (x_i + y_i)^{1/5}
            let sum = x_i + y_i;

            // Compute 5th root using modular exponentiation
            let sum_bigint = sum.into_bigint();
            let sum_biguint = bigint_to_biguint(&sum_bigint);
            let root_biguint = sum_biguint.modpow(&exp, &p);

            // Convert back to field element
            let root_bytes = root_biguint.to_bytes_le();
            let mut padded = [0u8; 32];
            let len = root_bytes.len().min(32);
            padded[..len].copy_from_slice(&root_bytes[..len]);
            let x_i_plus_1 = F::from_le_bytes_mod_order(&padded);

            let y_i_plus_1 = x_i;

            advice.push(MinRootIteration {
                x_i,
                y_i,
                x_i_plus_1,
                y_i_plus_1,
            });

            x_i = x_i_plus_1;
            y_i = y_i_plus_1;
        }

        ([x_0, y_0], Self { advice })
    }

    /// Create a circuit with empty advice (for setup/shape computation).
    pub fn empty(num_iters: usize) -> Self {
        Self {
            advice: vec![
                MinRootIteration {
                    x_i: F::zero(),
                    y_i: F::zero(),
                    x_i_plus_1: F::zero(),
                    y_i_plus_1: F::zero(),
                };
                num_iters
            ],
        }
    }
}

impl<F: PrimeField> StepCircuit<F, 2> for MinRootCircuit<F> {
    const NAME: &'static str = "MinRootCircuit";

    fn synthesize<E: CircuitEnv<F> + SelectorEnv<F>>(&self, env: &mut E, z: &[E::Variable; 2]) -> [E::Variable; 2] {
        let mut x_i = z[0].clone();
        let mut y_i = z[1].clone();

        for iter in &self.advice {
            // Allocate and write the non-deterministic 5th root
            let x_i_plus_1 = {
                let pos = env.allocate();
                env.write_column(pos, env.constant(iter.x_i_plus_1))
            };

            // Verify: x_{i+1}^5 = x_i + y_i
            // x^5 = x * x^2 * x^2 = x * (x^2)^2
            let x_sq = x_i_plus_1.clone() * x_i_plus_1.clone();
            let x_quad = x_sq.clone() * x_sq;
            let x_fifth = x_quad * x_i_plus_1.clone();

            let sum = x_i.clone() + y_i.clone();

            // Assert x^5 = x_i + y_i
            env.assert_eq(&x_fifth, &sum);

            // Update for next iteration
            y_i = x_i;
            x_i = x_i_plus_1;
        }

        [x_i, y_i]
    }

    fn output(&self, z: &[F; 2]) -> [F; 2] {
        let mut x = z[0];
        let mut y = z[1];

        for iter in &self.advice {
            // Verify the advice is correct
            let sum = x + y;
            let x_new = iter.x_i_plus_1;
            assert_eq!(x_new * x_new * x_new * x_new * x_new, sum);
            y = x;
            x = x_new;
        }

        [x, y]
    }
}

#[cfg(test)]
mod constraint_tests {
    use super::*;
    use crate::circuit::ConstraintEnv;
    use mina_curves::pasta::Fp;

    #[test]
    fn test_minroot_output() {
        let (z0, circuit) = MinRootCircuit::<Fp>::new(1, Fp::from(3u64), Fp::from(5u64));
        let z1 = circuit.output(&z0);

        // Verify the output satisfies the constraint
        let sum = z0[0] + z0[1];
        let x_fifth = z1[0] * z1[0] * z1[0] * z1[0] * z1[0];
        assert_eq!(x_fifth, sum, "x^5 should equal x_i + y_i");
        assert_eq!(z1[1], z0[0], "y_{{i+1}} should equal x_i");
    }

    #[test]
    fn test_minroot_constraints() {
        // Create a circuit with 1 iteration
        let (_, circuit) = MinRootCircuit::<Fp>::new(1, Fp::from(3u64), Fp::from(5u64));

        // Use constraint environment to count constraints
        let mut env = ConstraintEnv::<Fp>::new();
        let z = env.make_input_vars::<2>();
        let _ = circuit.synthesize(&mut env, &z);

        // Should have 1 constraint per iteration (x^5 = x_i + y_i)
        assert_eq!(
            env.num_constraints(),
            1,
            "MinRoot with 1 iteration should have 1 constraint"
        );

        // The constraint is: x^5 - (x_i + y_i) = 0
        // x is a witness (degree 1), x_i and y_i are inputs (degree 1)
        // x^5 has degree 5, sum has degree 1
        // So the constraint has degree 5
        let degrees = env.constraint_degrees();
        assert_eq!(degrees[0], 5, "MinRoot constraint should have degree 5");

        // Check all degrees are within MAX_DEGREE
        env.check_degrees()
            .expect("All constraints should have degree <= MAX_DEGREE");
    }

    #[test]
    fn test_minroot_multiple_iterations() {
        // Create a circuit with 3 iterations
        let (_, circuit) = MinRootCircuit::<Fp>::new(3, Fp::from(1u64), Fp::from(2u64));

        let mut env = ConstraintEnv::<Fp>::new();
        let z = env.make_input_vars::<2>();
        let _ = circuit.synthesize(&mut env, &z);

        // Should have 1 constraint per iteration
        assert_eq!(
            env.num_constraints(),
            3,
            "MinRoot with 3 iterations should have 3 constraints"
        );

        // All constraints should have degree 5
        for (i, deg) in env.constraint_degrees().iter().enumerate() {
            assert_eq!(*deg, 5, "Constraint {} should have degree 5", i);
        }
    }

    /// Regression test for circuit metrics (1 iteration).
    /// If this test fails, the circuit implementation has changed.
    #[test]
    fn test_minroot_metrics_single() {
        let (_, circuit) = MinRootCircuit::<Fp>::new(1, Fp::from(3u64), Fp::from(5u64));

        let mut env = ConstraintEnv::<Fp>::new();
        let z = env.make_input_vars::<2>();
        let _ = circuit.synthesize(&mut env, &z);

        assert_eq!(env.num_constraints(), 1, "constraints changed");
        assert_eq!(env.num_witness_allocations(), 1, "witness allocations changed");
        assert_eq!(env.max_degree(), 5, "max degree changed");
    }

    /// Regression test for circuit metrics (5 iterations).
    /// If this test fails, the circuit implementation has changed.
    #[test]
    fn test_minroot_metrics_five() {
        let (_, circuit) = MinRootCircuit::<Fp>::new(5, Fp::from(3u64), Fp::from(5u64));

        let mut env = ConstraintEnv::<Fp>::new();
        let z = env.make_input_vars::<2>();
        let _ = circuit.synthesize(&mut env, &z);

        assert_eq!(env.num_constraints(), 5, "constraints changed");
        assert_eq!(env.num_witness_allocations(), 5, "witness allocations changed");
        assert_eq!(env.max_degree(), 5, "max degree changed");
    }
}

/// Trace tests for MinRootCircuit.
///
/// This module tests witness generation using the Trace environment.
#[cfg(test)]
mod trace_tests {
    use ark_ff::{BigInteger, Field, PrimeField};
    use mina_curves::pasta::Fp;
    use num_bigint::BigUint;

    use crate::circuit::{StepCircuit, Trace};

    use super::MinRootCircuit;

    /// Compute the 5th root of a field element.
    /// Uses modular exponentiation: x^{(p-3)/5 * 5^{-1} mod (p-1)} = x^{1/5}
    fn fifth_root<F: PrimeField>(x: F) -> F {
        // Helper to convert ark BigInteger to BigUint
        fn bigint_to_biguint<B: BigInteger>(bigint: &B) -> BigUint {
            let bytes: Vec<u8> = bigint
                .as_ref()
                .iter()
                .flat_map(|limb| limb.to_le_bytes())
                .collect();
            BigUint::from_bytes_le(&bytes)
        }

        let modulus = F::MODULUS;
        let p = bigint_to_biguint(&modulus);
        let two = BigUint::from(2u64);
        let three = BigUint::from(3u64);
        let five = BigUint::from(5u64);
        let five_inv = five.modpow(&(&p - &two), &p);
        let exp = (&five_inv * (&p - &three)) % &p;

        let x_bigint = x.into_bigint();
        let x_biguint = bigint_to_biguint(&x_bigint);
        let root_biguint = x_biguint.modpow(&exp, &p);

        let root_bytes = root_biguint.to_bytes_le();
        let mut padded = [0u8; 32];
        let len = root_bytes.len().min(32);
        padded[..len].copy_from_slice(&root_bytes[..len]);
        F::from_le_bytes_mod_order(&padded)
    }

    #[test]
    fn test_minroot_circuit_trace() {
        let x0 = Fp::from(3u64);
        let y0 = Fp::from(5u64);

        let (z0, circuit) = MinRootCircuit::new(1, x0, y0);
        let expected_output = circuit.output(&z0);

        let mut env = Trace::<Fp>::new(16);
        let z = env.make_input_vars([x0, y0]);
        let output = circuit.synthesize(&mut env, &z);

        assert_eq!(output[0], expected_output[0]);
        assert_eq!(output[1], expected_output[1]);
    }

    #[test]
    fn test_minroot_circuit_chain() {
        let x0 = Fp::from(42u64);
        let y0 = Fp::from(17u64);

        // Run 3 iterations at once
        let (z0, circuit) = MinRootCircuit::new(3, x0, y0);
        let expected_output = circuit.output(&z0);

        let mut env = Trace::<Fp>::new(16);
        let z = env.make_input_vars([x0, y0]);
        let output = circuit.synthesize(&mut env, &z);

        assert_eq!(output[0], expected_output[0]);
        assert_eq!(output[1], expected_output[1]);
    }

    #[test]
    fn test_minroot_output_matches() {
        // Test various starting values
        let test_pairs: Vec<(u64, u64)> = vec![(1, 2), (3, 5), (42, 17), (100, 200)];

        for (x, y) in test_pairs {
            let x0 = Fp::from(x);
            let y0 = Fp::from(y);

            let (_, circuit) = MinRootCircuit::new(2, x0, y0);

            let mut env = Trace::<Fp>::new(16);
            let z = env.make_input_vars([x0, y0]);

            let synth_output = circuit.synthesize(&mut env, &z);
            let direct_output = circuit.output(&[x0, y0]);

            assert_eq!(synth_output[0], direct_output[0]);
            assert_eq!(synth_output[1], direct_output[1]);
        }
    }

    #[test]
    fn test_minroot_witness_structure() {
        let x0 = Fp::from(7u64);
        let y0 = Fp::from(11u64);

        let (_, circuit) = MinRootCircuit::new(1, x0, y0);
        let x_next = fifth_root(x0 + y0);

        let mut env = Trace::<Fp>::new(16);
        let z = env.make_input_vars([x0, y0]);
        let _ = circuit.synthesize(&mut env, &z);

        // Check witness structure:
        // Column 0: input x (7)
        // Column 1: input y (11)
        // Column 2: witness x_i_plus_1 (fifth_root(7 + 11))
        assert_eq!(env.get(0, 0), Some(&x0));
        assert_eq!(env.get(0, 1), Some(&y0));
        assert_eq!(env.get(0, 2), Some(&x_next));
    }

    #[test]
    fn test_minroot_verification() {
        // Verify that x_next^5 = x + y
        let x0 = Fp::from(123u64);
        let y0 = Fp::from(456u64);

        let sum = x0 + y0;
        let x_next = fifth_root(sum);

        // Verify: x_next^5 == sum
        assert_eq!(x_next.pow([5]), sum);

        // Now verify through the circuit
        let (_, circuit) = MinRootCircuit::new(1, x0, y0);

        let mut env = Trace::<Fp>::new(16);
        let z = env.make_input_vars([x0, y0]);
        let output = circuit.synthesize(&mut env, &z);

        // output[0] is x_next, output[1] is y_next = x0
        assert_eq!(output[0].pow([5]), sum);
        assert_eq!(output[1], x0);
    }
}
