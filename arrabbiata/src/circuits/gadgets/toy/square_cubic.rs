//! Square-Cubic composite gadget demonstrating typed gadget composition.
//!
//! This gadget chains SquaringGadget and CubicGadget using the type-safe
//! `Chain` combinator.

use super::{cubic::CubicGadget, squaring::SquaringGadget};
use crate::circuits::compose::Chain;

// ============================================================================
// SquareCubicGadget - Composite Typed Gadget
// ============================================================================

/// A type alias for the composite gadget: Chain<SquaringGadget, CubicGadget>.
///
/// Computes: x -> x^2 -> (x^2)^3 + x^2 + 5 = x^6 + x^2 + 5
///
/// This demonstrates type-safe gadget composition using the `Chain` combinator.
/// The type system ensures that SquaringGadget's Scalar output is compatible
/// with CubicGadget's Scalar input.
pub type SquareCubicGadget = Chain<SquaringGadget, CubicGadget>;

/// Create a new SquareCubicGadget.
pub fn square_cubic_gadget() -> SquareCubicGadget {
    Chain::new(SquaringGadget::new(), CubicGadget::new())
}

/// Number of rows for the SquareCubicGadget (SquaringGadget + CubicGadget).
pub const SQUARE_CUBIC_ROWS: usize = 2; // 1 + 1

#[cfg(test)]
mod constraint_tests {
    use super::*;
    use crate::{
        circuit::{CircuitEnv, ConstraintEnv},
        circuits::{
            compose::ScalarGadget,
            gadget::{Scalar, TypedGadget},
        },
    };
    use mina_curves::pasta::Fp;

    #[test]
    fn test_square_cubic_gadget_output() {
        let gadget = square_cubic_gadget();

        // x=2: x^2=4, then 4^3 + 4 + 5 = 64 + 4 + 5 = 73
        let input = Scalar(Fp::from(2u64));
        let output = TypedGadget::<Fp>::output(&gadget, &input);
        assert_eq!(output.0, Fp::from(73u64));

        // x=3: x^2=9, then 9^3 + 9 + 5 = 729 + 9 + 5 = 743
        let input = Scalar(Fp::from(3u64));
        let output = TypedGadget::<Fp>::output(&gadget, &input);
        assert_eq!(output.0, Fp::from(743u64));
    }

    #[test]
    fn test_square_cubic_gadget_constraints() {
        let gadget = square_cubic_gadget();

        let mut env = ConstraintEnv::<Fp>::new();
        let x_var = {
            let pos = env.allocate();
            env.read_position(pos)
        };
        let input = Scalar(x_var);
        let _ = gadget.synthesize_scalar(&mut env, input);

        // SquaringGadget: 1 constraint (degree 2)
        // CubicGadget: 1 constraint (degree 3)
        // Total: 2 constraints
        assert_eq!(env.num_constraints(), 2, "Should have 2 constraints");
        assert_eq!(env.max_degree(), 3, "Max degree should be 3 from cubic");
    }

    /// Regression test for gadget metrics.
    #[test]
    fn test_square_cubic_gadget_metrics() {
        let gadget = square_cubic_gadget();

        let mut env = ConstraintEnv::<Fp>::new();
        let x_var = {
            let pos = env.allocate();
            env.read_position(pos)
        };
        let input = Scalar(x_var);
        let _ = gadget.synthesize_scalar(&mut env, input);

        assert_eq!(env.num_constraints(), 2, "constraints changed");
        assert_eq!(
            env.num_witness_allocations(),
            3,
            "witness allocations changed"
        ); // 1 input + 2 outputs
        assert_eq!(env.max_degree(), 3, "max degree changed");
    }

    #[test]
    fn test_square_cubic_gadget_rows() {
        // SquaringGadget::ROWS (1) + CubicGadget::ROWS (1) = 2
        assert_eq!(SQUARE_CUBIC_ROWS, 2);
    }
}

/// Trace tests for SquareCubicGadget.
///
/// This module tests witness generation using the Trace environment.
#[cfg(test)]
mod trace_tests {
    use mina_curves::pasta::Fp;

    use crate::{
        circuit::{CircuitEnv, Trace},
        circuits::{
            compose::ScalarGadget,
            gadget::{Scalar, TypedGadget},
        },
    };

    use super::square_cubic_gadget;

    #[test]
    fn test_square_cubic_gadget_trace() {
        let gadget = square_cubic_gadget();
        let mut env = Trace::<Fp>::new(16);

        // Input: 2
        // x^2 = 4, then 4^3 + 4 + 5 = 64 + 4 + 5 = 73
        let input_val = Fp::from(2u64);
        let input_pos = env.allocate();
        let input_var = env.write_column(input_pos, input_val);
        let input = Scalar(input_var);

        let output = gadget.synthesize_scalar(&mut env, input);

        let expected = TypedGadget::<Fp>::output(&gadget, &Scalar(input_val));
        assert_eq!(output.0, expected.0);
        assert_eq!(output.0, Fp::from(73u64));
    }

    #[test]
    fn test_square_cubic_gadget_chain() {
        let gadget = square_cubic_gadget();
        let mut env = Trace::<Fp>::new(16);

        // Run 3 steps chained
        let mut current = Fp::from(2u64);
        for i in 0..3 {
            if i > 0 {
                env.next_row();
            }
            let input_pos = env.allocate();
            let input_var = env.write_column(input_pos, current);
            let input = Scalar(input_var);
            let output = gadget.synthesize_scalar(&mut env, input);
            current = output.0;
        }

        // Step 1: 2 -> 73
        // Step 2: 73 -> 73^2 = 5329, then 5329^3 + 5329 + 5 = large number
        // Step 3: ... (large number)

        // Just verify we're on row 2 and the chain executed
        assert_eq!(env.current_row(), 2);
        assert_eq!(env.get(0, 0), Some(&Fp::from(2u64))); // First input
        assert_eq!(env.get(1, 0), Some(&Fp::from(73u64))); // Second input (output of first)
    }

    #[test]
    fn test_square_cubic_gadget_output_matches_for_various_inputs() {
        let gadget = square_cubic_gadget();

        let test_values: Vec<u64> = vec![0, 1, 2, 3, 5, 7, 10];

        for val in test_values {
            let mut env = Trace::<Fp>::new(16);
            let input_val = Fp::from(val);
            let input_pos = env.allocate();
            let input_var = env.write_column(input_pos, input_val);
            let input = Scalar(input_var);

            let synth_output = gadget.synthesize_scalar(&mut env, input);
            let direct_output = TypedGadget::<Fp>::output(&gadget, &Scalar(input_val));

            assert_eq!(
                synth_output.0, direct_output.0,
                "synthesize output should match output() for input {}",
                val
            );

            // Verify: x^6 + x^2 + 5
            let x2 = val * val;
            let x6 = x2 * x2 * x2;
            let expected = x6 + x2 + 5;
            assert_eq!(
                synth_output.0,
                Fp::from(expected),
                "output should be {} for input {}",
                expected,
                val
            );
        }
    }

    #[test]
    fn test_square_cubic_gadget_witness_table_structure() {
        let gadget = square_cubic_gadget();
        let mut env = Trace::<Fp>::new(16);

        // Input: 3
        // x^2 = 9
        // x^6 + x^2 + 5 = 729 + 9 + 5 = 743
        let input_val = Fp::from(3u64);
        let input_pos = env.allocate();
        let input_var = env.write_column(input_pos, input_val);
        let input = Scalar(input_var);
        let output = gadget.synthesize_scalar(&mut env, input);

        // Check witness table structure:
        // Column 0: input (3)
        // Column 1: x_squared from SquaringGadget (9)
        // Column 2: cubic result from CubicGadget (743)
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
        assert_eq!(output.0, Fp::from(743u64), "Output should be 743");
    }

    #[test]
    fn test_square_cubic_gadget_zero_input() {
        let gadget = square_cubic_gadget();
        let mut env = Trace::<Fp>::new(16);

        // 0^2 = 0, 0^3 + 0 + 5 = 5
        let input_pos = env.allocate();
        let input_var = env.write_column(input_pos, Fp::from(0u64));
        let input = Scalar(input_var);
        let output = gadget.synthesize_scalar(&mut env, input);

        assert_eq!(output.0, Fp::from(5u64));
        assert_eq!(env.get(0, 0), Some(&Fp::from(0u64))); // input
        assert_eq!(env.get(0, 1), Some(&Fp::from(0u64))); // x^2
        assert_eq!(env.get(0, 2), Some(&Fp::from(5u64))); // result
    }
}
