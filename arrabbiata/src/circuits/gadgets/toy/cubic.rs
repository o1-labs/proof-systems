//! Cubic polynomial gadget.

use ark_ff::PrimeField;

use crate::{
    circuit::{CircuitEnv, SelectorEnv},
    circuits::{
        gadget::{Position, Row, Scalar, TypedGadget},
        selector::QCubic,
    },
};

// ============================================================================
// CubicGadget - Typed Gadget
// ============================================================================

/// A typed gadget that computes the cubic polynomial: x -> x^3 + x + 5.
///
/// This implements `TypedGadget` with `Scalar` input/output,
/// enabling type-safe composition with other gadgets via `Chain` and `Repeat`.
#[derive(Clone, Debug, Default)]
pub struct CubicGadget;

impl CubicGadget {
    /// Create a new cubic gadget.
    pub fn new() -> Self {
        Self
    }
}

const CUBIC_INPUT_POSITIONS: &[Position] = &[Position {
    col: 0,
    row: Row::Curr,
}];
const CUBIC_OUTPUT_POSITIONS: &[Position] = &[Position {
    col: 1,
    row: Row::Curr,
}];

impl<F: PrimeField> TypedGadget<F> for CubicGadget {
    type Selector = QCubic;
    type Input<V: Clone> = Scalar<V>;
    type Output<V: Clone> = Scalar<V>;
    const ROWS: usize = 1;

    fn input_positions() -> &'static [Position] {
        CUBIC_INPUT_POSITIONS
    }

    fn output_positions() -> &'static [Position] {
        CUBIC_OUTPUT_POSITIONS
    }

    fn synthesize<E: CircuitEnv<F> + SelectorEnv<F>>(
        &self,
        env: &mut E,
        input: Self::Input<E::Variable>,
    ) -> Self::Output<E::Variable> {
        let x = input.0.clone();

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

        Scalar(output)
    }

    fn output(&self, input: &Self::Input<F>) -> Self::Output<F> {
        let x = input.0;
        Scalar(x * x * x + x + F::from(5u64))
    }
}

#[cfg(test)]
mod constraint_tests {
    use super::*;
    use crate::circuit::ConstraintEnv;
    use mina_curves::pasta::Fp;

    #[test]
    fn test_cubic_gadget_output() {
        let gadget = CubicGadget::new();

        // y = x^3 + x + 5
        // x=0: y = 0 + 0 + 5 = 5
        let input = Scalar(Fp::from(0u64));
        let output = gadget.output(&input);
        assert_eq!(output.0, Fp::from(5u64));

        // x=5: y = 125 + 5 + 5 = 135
        let output2 = gadget.output(&output);
        assert_eq!(output2.0, Fp::from(135u64));
    }

    #[test]
    fn test_cubic_gadget_constraints() {
        let gadget = CubicGadget::new();

        let mut env = ConstraintEnv::<Fp>::new();
        let x_var = {
            let pos = env.allocate();
            env.read_position(pos)
        };
        let input = Scalar(x_var);
        let _ = gadget.synthesize(&mut env, input);

        // CubicGadget has 1 constraint: output = x^3 + x + 5
        assert_eq!(
            env.num_constraints(),
            1,
            "CubicGadget should have 1 constraint"
        );

        // The constraint has degree 3 (from x^3)
        let degrees = env.constraint_degrees();
        assert_eq!(degrees[0], 3, "Cubic constraint should have degree 3");

        env.check_degrees()
            .expect("All constraints should have degree <= MAX_DEGREE");
    }

    /// Regression test for gadget metrics.
    /// If this test fails, the gadget implementation has changed.
    #[test]
    fn test_cubic_gadget_metrics() {
        let gadget = CubicGadget::new();

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
        assert_eq!(env.max_degree(), 3, "max degree changed");
    }
}

/// Trace tests for CubicGadget.
#[cfg(test)]
mod trace_tests {
    use mina_curves::pasta::Fp;

    use crate::{
        circuit::{CircuitEnv, Trace},
        circuits::gadget::{Scalar, TypedGadget},
    };

    use super::CubicGadget;

    /// Verify that output positions correctly describe where outputs are written in the trace.
    #[test]
    fn test_cubic_gadget_output_positions_match_trace() {
        use crate::circuits::gadget::test_utils::verify_trace_positions;

        let gadget = CubicGadget::new();
        let mut env = Trace::<Fp>::new(16);

        // Input value
        let input_val = Fp::from(3u64);
        let x_pos = env.allocate();
        let x_var = env.write_column(x_pos, input_val);
        let input = Scalar(x_var);

        // Synthesize
        let _output = gadget.synthesize(&mut env, input);

        // Get expected output: y = x^3 + x + 5 = 27 + 3 + 5 = 35
        let expected_output = gadget.output(&Scalar(input_val));

        // Verify positions using helper
        let current_row = env.current_row();

        verify_trace_positions(
            &env,
            current_row,
            <CubicGadget as TypedGadget<Fp>>::input_positions(),
            &[input_val],
            "input",
        );

        verify_trace_positions(
            &env,
            current_row,
            <CubicGadget as TypedGadget<Fp>>::output_positions(),
            &[expected_output.0],
            "output",
        );
    }
}
