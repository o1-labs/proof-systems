//! MinRoot gadget - a verifiable delay function.
//!
//! This module provides:
//! - `MinRootGadget`: A single iteration of MinRoot as a `TypedGadget`
//!
//! The MinRoot VDF computes `x_{i+1} = (x_i + y_i)^{1/5}` and `y_{i+1} = x_i`.
//!
//! For multiple iterations, use `Repeat<MinRootGadget, N>` from the compose module.

use ark_ff::{BigInteger, PrimeField};
use num_bigint::BigUint;

use crate::{
    circuit::{CircuitEnv, SelectorEnv},
    circuits::{
        gadget::{Pair, Position, Row, TypedGadget},
        selector::QMinRoot,
    },
};

// ============================================================================
// MinRootGadget - Single Iteration TypedGadget
// ============================================================================

/// A single iteration of the MinRoot VDF as a typed gadget.
///
/// Computes: (x, y) -> (fifth_root(x + y), x)
///
/// The 5th root is provided as non-deterministic advice and verified
/// by checking `x_new^5 = x + y`.
///
/// # Example
///
/// ```
/// use arrabbiata::circuits::{MinRootGadget, Pair, TypedGadget};
/// use mina_curves::pasta::Fp;
///
/// // Create gadget with precomputed advice
/// let x = Fp::from(3u64);
/// let y = Fp::from(5u64);
/// let x_new = MinRootGadget::compute_fifth_root(x + y);
/// let gadget = MinRootGadget::new(x_new);
///
/// // Verify the output
/// let input = Pair::new(x, y);
/// let output = gadget.output(&input);
/// assert_eq!(output.second, x); // y_new = x
/// ```
#[derive(Clone, Debug)]
pub struct MinRootGadget<F: PrimeField> {
    /// The precomputed 5th root (non-deterministic advice).
    pub x_new: F,
}

impl<F: PrimeField> MinRootGadget<F> {
    /// Create a new MinRootGadget with the given advice value.
    pub fn new(x_new: F) -> Self {
        Self { x_new }
    }

    /// Create a gadget from input values by computing the 5th root.
    pub fn from_input(x: F, y: F) -> Self {
        let x_new = Self::compute_fifth_root(x + y);
        Self { x_new }
    }

    /// Compute the 5th root of a field element.
    ///
    /// Uses modular exponentiation: x^((p-3)/5 * 5^{-1} mod (p-1)) = x^{1/5}
    pub fn compute_fifth_root(x: F) -> F {
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
}

// MinRoot layout:
// Input: (x_i, y_i) at columns 0, 1
// Output: (x_new, x_i) at columns 2, 0 (x_new is allocated, x_i is passed through)
const MINROOT_INPUT_POSITIONS: &[Position] = &[
    Position {
        col: 0,
        row: Row::Curr,
    }, // x_i
    Position {
        col: 1,
        row: Row::Curr,
    }, // y_i
];
const MINROOT_OUTPUT_POSITIONS: &[Position] = &[
    Position {
        col: 2,
        row: Row::Curr,
    }, // x_new (allocated)
    Position {
        col: 0,
        row: Row::Curr,
    }, // x_i (pass-through as y_new)
];

impl<F: PrimeField> TypedGadget<F> for MinRootGadget<F> {
    type Selector = QMinRoot;
    type Input<V: Clone> = Pair<V>;
    type Output<V: Clone> = Pair<V>;

    const NAME: &'static str = "minroot";
    const DESCRIPTION: &'static str = "MinRoot VDF: computes 5th roots";
    const ARITY: usize = 2;
    const ROWS: usize = 1;

    fn input_positions() -> &'static [Position] {
        MINROOT_INPUT_POSITIONS
    }

    fn output_positions() -> &'static [Position] {
        MINROOT_OUTPUT_POSITIONS
    }

    fn synthesize<E: CircuitEnv<F> + SelectorEnv<F>>(
        &self,
        env: &mut E,
        input: Self::Input<E::Variable>,
    ) -> Self::Output<E::Variable> {
        let x_i = input.first;
        let y_i = input.second;

        // Allocate and write the non-deterministic 5th root
        let x_new = {
            let pos = env.allocate();
            env.write_column(pos, env.constant(self.x_new))
        };

        // Verify: x_new^5 = x_i + y_i
        // x^5 = x * x^2 * x^2 = x * (x^2)^2
        let x_sq = x_new.clone() * x_new.clone();
        let x_quad = x_sq.clone() * x_sq;
        let x_fifth = x_quad * x_new.clone();

        let sum = x_i.clone() + y_i;

        // Assert x^5 = x_i + y_i
        env.assert_eq(&x_fifth, &sum);

        // Output: (x_new, x_i)
        Pair::new(x_new, x_i)
    }

    fn output(&self, input: &Self::Input<F>) -> Self::Output<F> {
        let x = input.first;
        let y = input.second;

        // Verify the advice is correct
        let sum = x + y;
        let x_new = self.x_new;
        assert_eq!(
            x_new * x_new * x_new * x_new * x_new,
            sum,
            "Invalid MinRoot advice: x_new^5 != x + y"
        );

        Pair::new(x_new, x)
    }
}

#[cfg(test)]
mod constraint_tests {
    use super::*;
    use crate::circuit::ConstraintEnv;
    use mina_curves::pasta::Fp;

    #[test]
    fn test_minroot_gadget_output() {
        let x = Fp::from(3u64);
        let y = Fp::from(5u64);
        let gadget = MinRootGadget::from_input(x, y);

        let input = Pair::new(x, y);
        let output = gadget.output(&input);

        // Verify the output satisfies the constraint
        let sum = x + y;
        let x_fifth = output.first * output.first * output.first * output.first * output.first;
        assert_eq!(x_fifth, sum, "x^5 should equal x_i + y_i");
        assert_eq!(output.second, x, "y_{{i+1}} should equal x_i");
    }

    #[test]
    fn test_minroot_gadget_constraints() {
        let x = Fp::from(3u64);
        let y = Fp::from(5u64);
        let gadget = MinRootGadget::from_input(x, y);

        // Use constraint environment to count constraints
        let mut env = ConstraintEnv::<Fp>::new();
        let x_var = {
            let pos = env.allocate();
            env.read_position(pos)
        };
        let y_var = {
            let pos = env.allocate();
            env.read_position(pos)
        };
        let input = Pair::new(x_var, y_var);
        let _ = gadget.synthesize(&mut env, input);

        // Should have 1 constraint (x^5 = x_i + y_i)
        assert_eq!(
            env.num_constraints(),
            1,
            "MinRootGadget should have 1 constraint"
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

    /// Regression test for gadget metrics.
    /// If this test fails, the gadget implementation has changed.
    #[test]
    fn test_minroot_gadget_metrics() {
        let x = Fp::from(3u64);
        let y = Fp::from(5u64);
        let gadget = MinRootGadget::from_input(x, y);

        let mut env = ConstraintEnv::<Fp>::new();
        let x_var = {
            let pos = env.allocate();
            env.read_position(pos)
        };
        let y_var = {
            let pos = env.allocate();
            env.read_position(pos)
        };
        let input = Pair::new(x_var, y_var);
        let _ = gadget.synthesize(&mut env, input);

        assert_eq!(env.num_constraints(), 1, "constraints changed");
        assert_eq!(
            env.num_witness_allocations(),
            3,
            "witness allocations changed"
        ); // 2 inputs + 1 output
        assert_eq!(env.max_degree(), 5, "max degree changed");
    }
}

/// Trace tests for MinRootGadget.
///
/// This module tests witness generation using the Trace environment.
#[cfg(test)]
mod trace_tests {
    use ark_ff::Field;
    use mina_curves::pasta::Fp;

    use crate::{
        circuit::{CircuitEnv, Trace},
        circuits::gadget::{Pair, TypedGadget},
    };

    use super::MinRootGadget;

    #[test]
    fn test_minroot_gadget_trace() {
        let x0 = Fp::from(3u64);
        let y0 = Fp::from(5u64);
        let gadget = MinRootGadget::from_input(x0, y0);

        let mut env = Trace::<Fp>::new(16);
        let x_pos = env.allocate();
        let x_var = env.write_column(x_pos, x0);
        let y_pos = env.allocate();
        let y_var = env.write_column(y_pos, y0);
        let input = Pair::new(x_var, y_var);

        let output = gadget.synthesize(&mut env, input);

        let expected = gadget.output(&Pair::new(x0, y0));
        assert_eq!(output.first, expected.first);
        assert_eq!(output.second, expected.second);
    }

    #[test]
    fn test_minroot_gadget_chain() {
        let x0 = Fp::from(42u64);
        let y0 = Fp::from(17u64);

        // Run 3 iterations manually
        let mut current = Pair::new(x0, y0);
        let mut env = Trace::<Fp>::new(16);

        for i in 0..3 {
            if i > 0 {
                env.next_row();
            }
            let gadget = MinRootGadget::from_input(current.first, current.second);

            let x_pos = env.allocate();
            let x_var = env.write_column(x_pos, current.first);
            let y_pos = env.allocate();
            let y_var = env.write_column(y_pos, current.second);
            let input = Pair::new(x_var, y_var);

            let output = gadget.synthesize(&mut env, input);
            current = Pair::new(output.first, output.second);
        }

        // Verify we completed 3 iterations
        assert_eq!(env.current_row(), 2);
    }

    #[test]
    fn test_minroot_gadget_witness_structure() {
        let x0 = Fp::from(7u64);
        let y0 = Fp::from(11u64);
        let gadget = MinRootGadget::from_input(x0, y0);
        let x_next = MinRootGadget::compute_fifth_root(x0 + y0);

        let mut env = Trace::<Fp>::new(16);
        let x_pos = env.allocate();
        let x_var = env.write_column(x_pos, x0);
        let y_pos = env.allocate();
        let y_var = env.write_column(y_pos, y0);
        let input = Pair::new(x_var, y_var);
        let _ = gadget.synthesize(&mut env, input);

        // Check witness structure:
        // Column 0: input x (7)
        // Column 1: input y (11)
        // Column 2: witness x_i_plus_1 (fifth_root(7 + 11))
        assert_eq!(env.get(0, 0), Some(&x0));
        assert_eq!(env.get(0, 1), Some(&y0));
        assert_eq!(env.get(0, 2), Some(&x_next));
    }

    #[test]
    fn test_minroot_gadget_verification() {
        // Verify that x_next^5 = x + y
        let x0 = Fp::from(123u64);
        let y0 = Fp::from(456u64);
        let gadget = MinRootGadget::from_input(x0, y0);

        let sum = x0 + y0;
        let x_next = MinRootGadget::compute_fifth_root(sum);

        // Verify: x_next^5 == sum
        assert_eq!(x_next.pow([5]), sum);

        // Now verify through the gadget
        let mut env = Trace::<Fp>::new(16);
        let x_pos = env.allocate();
        let x_var = env.write_column(x_pos, x0);
        let y_pos = env.allocate();
        let y_var = env.write_column(y_pos, y0);
        let input = Pair::new(x_var, y_var);
        let output = gadget.synthesize(&mut env, input);

        // output.first is x_next, output.second is y_next = x0
        assert_eq!(output.first.pow([5]), sum);
        assert_eq!(output.second, x0);
    }
}

/// Tests for MinRootGadget (TypedGadget implementation).
#[cfg(test)]
mod gadget_tests {
    use mina_curves::pasta::Fp;

    use crate::{
        circuit::{CircuitEnv, ConstraintEnv, Trace},
        circuits::gadget::{Pair, TypedGadget},
    };

    use super::MinRootGadget;

    #[test]
    fn test_minroot_gadget_output() {
        let x = Fp::from(3u64);
        let y = Fp::from(5u64);
        let gadget = MinRootGadget::from_input(x, y);

        let input = Pair::new(x, y);
        let output = gadget.output(&input);

        // Verify x_new^5 = x + y
        let x_new = output.first;
        let sum = x + y;
        assert_eq!(x_new * x_new * x_new * x_new * x_new, sum);

        // Verify y_new = x
        assert_eq!(output.second, x);
    }

    #[test]
    fn test_minroot_gadget_fifth_root() {
        // Test the fifth root computation
        let x = Fp::from(42u64);
        let fifth_root = MinRootGadget::compute_fifth_root(x);

        // Verify: fifth_root^5 = x
        assert_eq!(
            fifth_root * fifth_root * fifth_root * fifth_root * fifth_root,
            x
        );
    }

    #[test]
    fn test_minroot_gadget_constraint_env() {
        let x = Fp::from(7u64);
        let y = Fp::from(11u64);
        let gadget = MinRootGadget::from_input(x, y);

        let mut env = ConstraintEnv::<Fp>::new();
        let x_var = {
            let pos = env.allocate();
            env.read_position(pos)
        };
        let y_var = {
            let pos = env.allocate();
            env.read_position(pos)
        };
        let input = Pair::new(x_var, y_var);

        let _output = gadget.synthesize(&mut env, input);

        // Should have 1 constraint (x_new^5 = x + y)
        assert_eq!(env.num_constraints(), 1);

        // Degree should be 5 (x_new^5)
        assert_eq!(env.max_degree(), 5);
    }

    #[test]
    fn test_minroot_gadget_trace() {
        let x = Fp::from(100u64);
        let y = Fp::from(200u64);
        let gadget = MinRootGadget::from_input(x, y);

        let mut env = Trace::<Fp>::new(16);

        // Write input variables
        let x_pos = env.allocate();
        let x_var = env.write_column(x_pos, x);
        let y_pos = env.allocate();
        let y_var = env.write_column(y_pos, y);
        let input = Pair::new(x_var, y_var);

        let output = gadget.synthesize(&mut env, input);

        // Verify output matches expected
        let expected = gadget.output(&Pair::new(x, y));
        assert_eq!(output.first, expected.first);
        assert_eq!(output.second, expected.second);
    }

    #[test]
    fn test_minroot_gadget_rows() {
        // MinRootGadget should use 1 row
        assert_eq!(<MinRootGadget<Fp> as TypedGadget<Fp>>::ROWS, 1);
    }

    #[test]
    fn test_minroot_gadget_various_inputs() {
        let test_pairs: Vec<(u64, u64)> = vec![(1, 2), (3, 5), (42, 17), (0, 100)];

        for (x_val, y_val) in test_pairs {
            let x = Fp::from(x_val);
            let y = Fp::from(y_val);
            let gadget = MinRootGadget::from_input(x, y);

            let input = Pair::new(x, y);
            let output = gadget.output(&input);

            // Verify constraint: x_new^5 = x + y
            let x_new = output.first;
            let sum = x + y;
            assert_eq!(
                x_new * x_new * x_new * x_new * x_new,
                sum,
                "Failed for ({}, {})",
                x_val,
                y_val
            );

            // Verify y_new = x
            assert_eq!(
                output.second, x,
                "y_new should equal x for ({}, {})",
                x_val, y_val
            );
        }
    }

    /// Verify that output positions correctly describe where outputs are written in the trace.
    #[test]
    fn test_minroot_gadget_output_positions_match_trace() {
        use crate::circuits::gadget::test_utils::verify_trace_positions;

        let x = Fp::from(7u64);
        let y = Fp::from(11u64);
        let gadget = MinRootGadget::from_input(x, y);
        let mut env = Trace::<Fp>::new(16);

        // Write input values
        let x_pos = env.allocate();
        let x_var = env.write_column(x_pos, x);
        let y_pos = env.allocate();
        let y_var = env.write_column(y_pos, y);
        let input = Pair::new(x_var, y_var);

        // Synthesize
        let _output = gadget.synthesize(&mut env, input);

        // Get expected output
        let expected_output = gadget.output(&Pair::new(x, y));

        // Verify positions using helper
        let current_row = env.current_row();

        verify_trace_positions(
            &env,
            current_row,
            <MinRootGadget<Fp> as TypedGadget<Fp>>::input_positions(),
            &[x, y],
            "input",
        );

        verify_trace_positions(
            &env,
            current_row,
            <MinRootGadget<Fp> as TypedGadget<Fp>>::output_positions(),
            &[expected_output.first, expected_output.second],
            "output",
        );
    }
}
