//! Elliptic curve point doubling circuit gadget.
//!
//! This module implements specialized elliptic curve point doubling.
//!
//! # Gadget
//!
//! - [`CurveNativeDoubleGadget`]: Computes 2*P for a given point P.
//!
//! # Type Safety
//!
//! The gadget is parameterized by a curve type `C` implementing [`SWCurveConfig`],
//! which guarantees at compile time that:
//! 1. The curve is in short Weierstrass form (y² = x³ + ax + b)
//! 2. Points are in affine coordinates (x, y)
//!
//! # Layout
//!
//! For [`CurveNativeDoubleGadget`] with input (x1, y1):
//!
//! ```text
//! | C1 | C2 | C3 | C4 | C5 |
//! | -- | -- | -- | -- | -- |
//! | x1 | y1 | λ  | x3 | y3 |
//! ```
//!
//! Where:
//! - (x1, y1): Input point P1 in affine coordinates
//! - λ: Slope for the doubling formula
//! - (x3, y3): Output point 2*P1 in affine coordinates
//!
//! # Constraints
//!
//! - λ * 2Y1 - 3X1² - a = 0 (slope constraint)
//! - X3 + 2X1 - λ² = 0 (output X constraint)
//! - Y3 - λ(X1 - X3) + Y1 = 0 (output Y constraint)

use ark_ec::short_weierstrass::SWCurveConfig;
use ark_ff::{Field, PrimeField, Zero};
use core::marker::PhantomData;

use crate::{
    circuit::{CircuitEnv, SelectorEnv},
    circuits::{
        gadget::{ECPoint, Position, Row, TypedGadget},
        selector::QECAdd,
    },
};

// Position constants for CurveNativeDoubleGadget
// Layout: | x1 | y1 | λ  | x3 | y3 |
//         |  0 |  1 |  2 |  3 |  4 |
const EC_DOUBLE_INPUT_POSITIONS: &[Position] = &[
    Position {
        col: 0,
        row: Row::Curr,
    }, // x1
    Position {
        col: 1,
        row: Row::Curr,
    }, // y1
];
const EC_DOUBLE_OUTPUT_POSITIONS: &[Position] = &[
    Position {
        col: 3,
        row: Row::Curr,
    }, // x3 (result)
    Position {
        col: 4,
        row: Row::Curr,
    }, // y3 (result)
];

/// Native field EC point doubling gadget (specialized version).
///
/// Computes P2 = 2*P1 where P1 = (x1, y1).
/// This is a specialized version when we know both inputs are the same.
///
/// The gadget is parameterized by a curve type `C` implementing [`SWCurveConfig`],
/// which guarantees at compile time that:
/// 1. The curve is in short Weierstrass form (y² = x³ + ax + b)
/// 2. Points are in affine coordinates
///
/// # Type Parameters
///
/// - `C`: A curve configuration implementing [`SWCurveConfig`]
pub struct CurveNativeDoubleGadget<C: SWCurveConfig> {
    _marker: PhantomData<C>,
}

impl<C: SWCurveConfig> Clone for CurveNativeDoubleGadget<C> {
    fn clone(&self) -> Self {
        Self {
            _marker: PhantomData,
        }
    }
}

impl<C: SWCurveConfig> core::fmt::Debug for CurveNativeDoubleGadget<C> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CurveNativeDoubleGadget").finish()
    }
}

impl<C: SWCurveConfig> CurveNativeDoubleGadget<C>
where
    C::BaseField: PrimeField,
{
    /// Create a new native EC doubling gadget.
    ///
    /// The curve type `C` must implement [`SWCurveConfig`], which provides
    /// the curve coefficients and ensures the curve is in short Weierstrass form.
    pub fn new() -> Self {
        Self {
            _marker: PhantomData,
        }
    }
}

impl<C: SWCurveConfig> Default for CurveNativeDoubleGadget<C>
where
    C::BaseField: PrimeField,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<C: SWCurveConfig> PartialEq for CurveNativeDoubleGadget<C> {
    fn eq(&self, _other: &Self) -> bool {
        true
    }
}

impl<C: SWCurveConfig> Eq for CurveNativeDoubleGadget<C> {}

impl<C: SWCurveConfig> TypedGadget<C::BaseField> for CurveNativeDoubleGadget<C>
where
    C::BaseField: PrimeField,
{
    type Selector = QECAdd;
    type Input<V: Clone> = ECPoint<V>;
    type Output<V: Clone> = ECPoint<V>;

    const NAME: &'static str = "ec-double";
    const DESCRIPTION: &'static str = "Elliptic curve point doubling";
    const ARITY: usize = 2;
    const ROWS: usize = 1;

    fn input_positions() -> &'static [Position] {
        EC_DOUBLE_INPUT_POSITIONS
    }

    fn output_positions() -> &'static [Position] {
        EC_DOUBLE_OUTPUT_POSITIONS
    }

    fn synthesize<E: CircuitEnv<C::BaseField> + SelectorEnv<C::BaseField>>(
        &self,
        env: &mut E,
        input: Self::Input<E::Variable>,
    ) -> Self::Output<E::Variable> {
        let x1 = input.x;
        let y1 = input.y;

        // Try to extract concrete values for witness computation
        let (lambda_val, x3_val, y3_val) = match (env.try_as_field(&x1), env.try_as_field(&y1)) {
            (Some(x1_f), Some(y1_f)) => {
                // In witness mode: compute actual values
                // λ = (3x1² + a) / (2y1)
                let numerator = C::BaseField::from(3u64) * x1_f * x1_f + C::COEFF_A;
                let denominator = C::BaseField::from(2u64) * y1_f;
                let lambda_f = numerator * denominator.inverse().unwrap();

                // X3 = λ² - 2X1
                let x3_f = lambda_f * lambda_f - C::BaseField::from(2u64) * x1_f;

                // Y3 = λ (X1 - X3) - Y1
                let y3_f = lambda_f * (x1_f - x3_f) - y1_f;

                (lambda_f, x3_f, y3_f)
            }
            _ => {
                // In constraint mode: use placeholder values (constraints are symbolic)
                (
                    C::BaseField::zero(),
                    C::BaseField::zero(),
                    C::BaseField::zero(),
                )
            }
        };

        // λ = (3x1² + a) / (2y1)
        // Constraint: λ * 2y1 = 3x1² + a
        let lambda = {
            let pos = env.allocate();
            env.write_column(pos, env.constant(lambda_val))
        };

        // Allocate x3 as witness
        let x3 = {
            let pos = env.allocate();
            env.write_column(pos, env.constant(x3_val))
        };

        // Allocate y3 as witness
        let y3 = {
            let pos = env.allocate();
            env.write_column(pos, env.constant(y3_val))
        };

        let two = env.constant(C::BaseField::from(2u64));
        let three = env.constant(C::BaseField::from(3u64));

        let two_y1 = two.clone() * y1.clone();
        let lambda_times_2y1 = lambda.clone() * two_y1;

        let x1_squared = x1.clone() * x1.clone();
        let three_x1_squared = three * x1_squared;
        let a_const = env.constant(C::COEFF_A);
        let three_x1_squared_plus_a = three_x1_squared + a_const;

        // Constraint 1: λ * 2y1 = 3x1² + a
        let constraint = lambda_times_2y1 - three_x1_squared_plus_a;
        env.assert_zero_named("double_slope", &constraint);

        // Constraint 2: X3 = λ² - 2X1
        // Rearranged: X3 + 2X1 - λ² = 0
        let lambda_squared = lambda.clone() * lambda.clone();
        let two_x1 = two * x1.clone();
        let x3_constraint = x3.clone() + two_x1 - lambda_squared;
        env.assert_zero_named("double_x3", &x3_constraint);

        // Constraint 3: Y3 = λ (X1 - X3) - Y1
        // Rearranged: Y3 - λ(X1 - X3) + Y1 = 0
        let x1_minus_x3 = x1 - x3.clone();
        let lambda_times_diff = lambda * x1_minus_x3;
        let y3_constraint = y3.clone() - lambda_times_diff + y1;
        env.assert_zero_named("double_y3", &y3_constraint);

        ECPoint::new(x3, y3)
    }

    fn output(&self, input: &Self::Input<C::BaseField>) -> Self::Output<C::BaseField> {
        let x1 = input.x;
        let y1 = input.y;

        // λ = (3x1² + a) / (2y1)
        let numerator = C::BaseField::from(3u64) * x1 * x1 + C::COEFF_A;
        let denominator = C::BaseField::from(2u64) * y1;
        let lambda = numerator * denominator.inverse().unwrap();

        // X3 = λ² - 2X1
        let x3 = lambda * lambda - C::BaseField::from(2u64) * x1;

        // Y3 = λ (X1 - X3) - Y1
        let y3 = lambda * (x1 - x3) - y1;

        ECPoint::new(x3, y3)
    }
}

// ============================================================================
// Constraint tests
// ============================================================================

#[cfg(test)]
mod constraint_tests {
    use super::*;
    use crate::{circuit::ConstraintEnv, circuits::selector::SelectorTag};
    use mina_curves::pasta::{Fp, PallasParameters};

    #[test]
    fn test_curve_native_double_gadget_constraints() {
        let gadget = CurveNativeDoubleGadget::<PallasParameters>::new();

        let mut env = ConstraintEnv::<Fp>::new();

        // Create input
        let input = {
            let x1_pos = env.allocate();
            let x1 = env.read_position(x1_pos);
            let y1_pos = env.allocate();
            let y1 = env.read_position(y1_pos);
            ECPoint::new(x1, y1)
        };

        let _ = gadget.synthesize(&mut env, input);

        // CurveNativeDoubleGadget has 3 constraints:
        // 1. λ * 2y1 = 3x1² + a (slope)
        // 2. x3 + 2x1 - λ² = 0 (x3)
        // 3. y3 - λ(x1 - x3) + y1 = 0 (y3)
        assert_eq!(
            env.num_constraints(),
            3,
            "CurveNativeDoubleGadget should have 3 constraints"
        );

        // The constraints have degree 2 (λ * y1 is degree 2, x1² is degree 2, λ² is degree 2)
        assert_eq!(env.max_degree(), 2, "Max degree should be 2");

        // 3 witness allocations for λ, x3, y3 (plus 2 for inputs)
        assert_eq!(
            env.num_witness_allocations(),
            5,
            "Should have 5 allocations (2 inputs + λ + x3 + y3)"
        );

        env.check_degrees()
            .expect("All constraints should have degree <= MAX_DEGREE");
    }

    #[test]
    fn test_curve_native_double_gadget_selector() {
        assert_eq!(
            <CurveNativeDoubleGadget<PallasParameters> as TypedGadget<Fp>>::Selector::GADGET,
            crate::column::Gadget::EllipticCurveAddition
        );
        assert_eq!(
            <CurveNativeDoubleGadget<PallasParameters> as TypedGadget<Fp>>::Selector::INDEX,
            8
        );
    }
}

// ============================================================================
// Output correctness tests
// ============================================================================

#[cfg(test)]
mod output_tests {
    use super::*;
    use ark_ec::AffineRepr;
    use mina_curves::pasta::{Pallas, PallasParameters};
    use rand::{Rng, SeedableRng};

    #[test]
    fn test_curve_native_double_gadget_output() {
        let gadget = CurveNativeDoubleGadget::<PallasParameters>::new();

        let g = Pallas::generator();
        let input = ECPoint::new(g.x, g.y);
        let output = gadget.output(&input);

        let g2: Pallas = (Pallas::generator() + Pallas::generator()).into();

        assert_eq!(output.x, g2.x, "X coordinate of 2G should match");
        assert_eq!(output.y, g2.y, "Y coordinate of 2G should match");
    }

    #[test]
    fn test_curve_native_double_gadget_random_point() {
        let seed: u64 = rand::random();
        println!("test_curve_native_double_gadget_random_point seed: {seed}");
        let mut rng = rand::rngs::StdRng::seed_from_u64(seed);

        let gadget = CurveNativeDoubleGadget::<PallasParameters>::new();

        // Generate random scalar and compute random point
        let scalar: u64 = rng.gen();
        let p: Pallas = Pallas::generator().mul_bigint([scalar]).into();

        let input = ECPoint::new(p.x, p.y);
        let output = gadget.output(&input);

        // Verify against arkworks
        let doubled: Pallas = (p + p).into();

        assert_eq!(output.x, doubled.x, "X coordinate should match arkworks");
        assert_eq!(output.y, doubled.y, "Y coordinate should match arkworks");
    }

    #[test]
    fn test_curve_native_double_gadget_deterministic() {
        let gadget = CurveNativeDoubleGadget::<PallasParameters>::new();

        let g = Pallas::generator();
        let input = ECPoint::new(g.x, g.y);

        let output1 = gadget.output(&input);
        let output2 = gadget.output(&input);

        assert_eq!(output1, output2, "Same inputs should give same outputs");
    }

    /// Verify that output positions correctly describe where outputs are written in the trace.
    #[test]
    fn test_curve_native_double_gadget_output_positions_match_trace() {
        use crate::{
            circuit::{CircuitEnv, Trace},
            circuits::gadget::test_utils::verify_trace_positions,
        };
        use mina_curves::pasta::Fp;

        let gadget = CurveNativeDoubleGadget::<PallasParameters>::new();
        let mut env = Trace::<Fp>::new(16);

        // Use the generator as input point
        let g = Pallas::generator();
        let (x1, y1) = (g.x, g.y);

        // Allocate and write input point
        let x1_pos = env.allocate();
        let x1_var = env.write_column(x1_pos, x1);
        let y1_pos = env.allocate();
        let y1_var = env.write_column(y1_pos, y1);
        let input = ECPoint::new(x1_var, y1_var);

        // Synthesize
        let _output = gadget.synthesize(&mut env, input);

        // Compute expected output using the output() method
        let expected_output = gadget.output(&ECPoint::new(x1, y1));

        // Verify positions using helper
        let current_row = env.current_row();

        verify_trace_positions(
            &env,
            current_row,
            <CurveNativeDoubleGadget<PallasParameters> as TypedGadget<Fp>>::input_positions(),
            &[x1, y1],
            "input",
        );

        verify_trace_positions(
            &env,
            current_row,
            <CurveNativeDoubleGadget<PallasParameters> as TypedGadget<Fp>>::output_positions(),
            &[expected_output.x, expected_output.y],
            "output",
        );
    }
}
