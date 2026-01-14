//! Elliptic curve addition circuit gadget.
//!
//! This module implements elliptic curve point addition as a typed gadget
//! that can be composed to build the IVC verifier circuit.
//!
//! # Gadget
//!
//! - [`CurveNativeAddGadget`]: General point addition with automatic doubling detection.
//!   Handles both P1 + P2 (different points) and 2*P (same point).
//!
//! # Type Safety
//!
//! The gadget is parameterized by a curve type `C` implementing [`SWCurveConfig`],
//! which guarantees at compile time that:
//! 1. The curve is in short Weierstrass form (y² = x³ + ax + b)
//! 2. Points are in affine coordinates (x, y)
//!
//! This enables type-safe circuit composition: when combining gadgets
//! (e.g., scalar multiplication using additions), the curve types are checked
//! at compile time, preventing mismatched curves.
//!
//! # Layout
//!
//! For [`CurveNativeAddGadget`] with inputs (x1, y1) and (x2, y2):
//!
//! ```text
//! | C1 | C2 | C3 | C4 | C5 | C6 | C7 | C8 |
//! | -- | -- | -- | -- | -- | -- | -- | -- |
//! | x1 | y1 | x2 | y2 | b0 | λ  | x3 | y3 |
//! ```
//!
//! Where:
//! - (x1, y1): First input point P1 in affine coordinates
//! - (x2, y2): Second input point P2 in affine coordinates
//! - b0: Boolean flag, 1 if points are the same (doubling case)
//! - λ: Slope for the addition formula
//! - (x3, y3): Output point P3 = P1 + P2 in affine coordinates
//!
//! # Constraints
//!
//! For different points (b0 = 0):
//! - λ (X1 - X2) - Y1 + Y2 = 0
//! - X3 + X1 + X2 - λ² = 0
//! - Y3 - λ (X1 - X3) + Y1 = 0
//!
//! For doubling (b0 = 1):
//! - λ * 2Y1 - 3X1² - a = 0
//! - X3 + 2X1 - λ² = 0
//! - Y3 - λ (X1 - X3) + Y1 = 0

use ark_ec::short_weierstrass::SWCurveConfig;
use ark_ff::{Field, One, PrimeField, Zero};
use core::marker::PhantomData;

use crate::{
    circuit::{CircuitEnv, SelectorEnv},
    circuits::{
        gadget::{ECPoint, ECPointPair, Position, Row, TypedGadget},
        selector::QECAdd,
    },
};

// Position constants for CurveNativeAddGadget
// Layout: | x1 | y1 | x2 | y2 | b0 | λ  | x3 | y3 |
//         |  0 |  1 |  2 |  3 |  4 | 5  |  6 |  7 |
const EC_ADD_INPUT_POSITIONS: &[Position] = &[
    Position {
        col: 0,
        row: Row::Curr,
    }, // x1
    Position {
        col: 1,
        row: Row::Curr,
    }, // y1
    Position {
        col: 2,
        row: Row::Curr,
    }, // x2
    Position {
        col: 3,
        row: Row::Curr,
    }, // y2
];
const EC_ADD_OUTPUT_POSITIONS: &[Position] = &[
    Position {
        col: 6,
        row: Row::Curr,
    }, // x3 (result)
    Position {
        col: 7,
        row: Row::Curr,
    }, // y3 (result)
    Position {
        col: 0,
        row: Row::Curr,
    }, // x1 (original, for chaining)
    Position {
        col: 1,
        row: Row::Curr,
    }, // y1 (original, for chaining)
];

/// Native field elliptic curve addition gadget.
///
/// Computes P3 = P1 + P2 where P1 = (x1, y1) and P2 = (x2, y2).
/// Handles both the general addition case and point doubling.
///
/// "Native" means the curve's base field matches the circuit's field.
///
/// The gadget is parameterized by a curve type `C` implementing [`SWCurveConfig`],
/// which guarantees at compile time that:
/// 1. The curve is in short Weierstrass form (y² = x³ + ax + b)
/// 2. Points are in affine coordinates
///
/// # Type Parameters
///
/// - `C`: A curve configuration implementing [`SWCurveConfig`]
///
/// # Input/Output Format
///
/// Input: `ECPointPair<V>` containing (P1, P2)
/// Output: `ECPointPair<V>` containing (P3, P1) where P3 = P1 + P2
///
/// This allows chaining: the result can be used as the first point
/// for the next addition.
pub struct CurveNativeAddGadget<C: SWCurveConfig> {
    _marker: PhantomData<C>,
}

impl<C: SWCurveConfig> Clone for CurveNativeAddGadget<C> {
    fn clone(&self) -> Self {
        Self {
            _marker: PhantomData,
        }
    }
}

impl<C: SWCurveConfig> core::fmt::Debug for CurveNativeAddGadget<C> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CurveNativeAddGadget").finish()
    }
}

impl<C: SWCurveConfig> CurveNativeAddGadget<C>
where
    C::BaseField: PrimeField,
{
    /// Create a new native EC addition gadget.
    ///
    /// The curve type `C` must implement [`SWCurveConfig`], which provides
    /// the curve coefficients and ensures the curve is in short Weierstrass form.
    pub fn new() -> Self {
        Self {
            _marker: PhantomData,
        }
    }

    /// Compute λ (slope) for point addition.
    ///
    /// For different points: λ = (y1 - y2) / (x1 - x2)
    /// For same point: λ = (3x1² + a) / (2y1)
    fn compute_lambda(
        x1: C::BaseField,
        y1: C::BaseField,
        x2: C::BaseField,
        y2: C::BaseField,
        is_same: bool,
    ) -> C::BaseField {
        if is_same {
            // Doubling: λ = (3x1² + a) / (2y1)
            let numerator = C::BaseField::from(3u64) * x1 * x1 + C::COEFF_A;
            let denominator = C::BaseField::from(2u64) * y1;
            numerator * denominator.inverse().unwrap()
        } else {
            // Different points: λ = (y1 - y2) / (x1 - x2)
            let numerator = y1 - y2;
            let denominator = x1 - x2;
            numerator * denominator.inverse().unwrap()
        }
    }

    /// Check if two points are the same.
    fn is_same_point(
        x1: C::BaseField,
        y1: C::BaseField,
        x2: C::BaseField,
        y2: C::BaseField,
    ) -> bool {
        x1 == x2 && y1 == y2
    }
}

impl<C: SWCurveConfig> Default for CurveNativeAddGadget<C>
where
    C::BaseField: PrimeField,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<C: SWCurveConfig> PartialEq for CurveNativeAddGadget<C> {
    fn eq(&self, _other: &Self) -> bool {
        true
    }
}

impl<C: SWCurveConfig> Eq for CurveNativeAddGadget<C> {}

impl<C: SWCurveConfig> TypedGadget<C::BaseField> for CurveNativeAddGadget<C>
where
    C::BaseField: PrimeField,
{
    type Selector = QECAdd;
    type Input<V: Clone> = ECPointPair<V>;
    type Output<V: Clone> = ECPointPair<V>;
    const ROWS: usize = 1;

    fn input_positions() -> &'static [Position] {
        EC_ADD_INPUT_POSITIONS
    }

    fn output_positions() -> &'static [Position] {
        EC_ADD_OUTPUT_POSITIONS
    }

    fn synthesize<E: CircuitEnv<C::BaseField> + SelectorEnv<C::BaseField>>(
        &self,
        env: &mut E,
        input: Self::Input<E::Variable>,
    ) -> Self::Output<E::Variable> {
        // Input points: P1 = (x1, y1), P2 = (x2, y2)
        let x1 = input.p1.x;
        let y1 = input.p1.y;
        let x2 = input.p2.x;
        let y2 = input.p2.y;

        // Boolean flag for same point (witness)
        let is_same = {
            let pos = env.allocate();
            env.write_column(pos, env.constant(C::BaseField::zero()))
        };

        // Compute λ (witness)
        let lambda = {
            let pos = env.allocate();
            env.write_column(pos, env.constant(C::BaseField::zero()))
        };

        // Constraint 1: is_same is boolean
        // is_same * (1 - is_same) = 0
        let one = env.constant(C::BaseField::one());
        let one_minus_is_same = one.clone() - is_same.clone();
        let is_same_times_complement = is_same.clone() * one_minus_is_same.clone();
        env.assert_zero_named("is_same_boolean", &is_same_times_complement);

        // Constraint 2: Different point slope
        // (1 - is_same) * (λ * (x1 - x2) - (y1 - y2)) = 0
        let x1_minus_x2 = x1.clone() - x2.clone();
        let y1_minus_y2 = y1.clone() - y2.clone();
        let lambda_times_dx = lambda.clone() * x1_minus_x2;
        let diff_constraint = lambda_times_dx - y1_minus_y2;
        let diff_check = one_minus_is_same * diff_constraint;
        env.assert_zero_named("add_slope", &diff_check);

        // Constraint 3: Doubling slope
        // is_same * (λ * 2y1 - 3x1² - a) = 0
        let two = env.constant(C::BaseField::from(2u64));
        let three = env.constant(C::BaseField::from(3u64));
        let two_y1 = two.clone() * y1.clone();
        let lambda_times_2y1 = lambda.clone() * two_y1;
        let x1_squared = x1.clone() * x1.clone();
        let three_x1_squared = three * x1_squared;
        let a_const = env.constant(C::COEFF_A);
        let three_x1_squared_plus_a = three_x1_squared + a_const;
        let double_constraint = lambda_times_2y1 - three_x1_squared_plus_a;
        let double_check = is_same * double_constraint;
        env.assert_zero_named("double_slope", &double_check);

        // Output point: X3 = λ² - X1 - X2
        let lambda_squared = lambda.clone() * lambda.clone();
        let x3_temp = lambda_squared - x1.clone();
        let x3 = x3_temp - x2;

        // Y3 = λ (X1 - X3) - Y1
        let x1_minus_x3 = x1.clone() - x3.clone();
        let lambda_times_diff = lambda * x1_minus_x3;
        let y3 = lambda_times_diff - y1.clone();

        // Return result P3 as p1 and original P1 as p2 for chaining
        ECPointPair::new(ECPoint::new(x3, y3), ECPoint::new(x1, y1))
    }

    fn output(&self, input: &Self::Input<C::BaseField>) -> Self::Output<C::BaseField> {
        let x1 = input.p1.x;
        let y1 = input.p1.y;
        let x2 = input.p2.x;
        let y2 = input.p2.y;

        let is_same = Self::is_same_point(x1, y1, x2, y2);
        let lambda = Self::compute_lambda(x1, y1, x2, y2, is_same);

        // X3 = λ² - X1 - X2
        let x3 = lambda * lambda - x1 - x2;

        // Y3 = λ (X1 - X3) - Y1
        let y3 = lambda * (x1 - x3) - y1;

        // Return result P3 as p1 and original P1 as p2 for chaining
        ECPointPair::new(ECPoint::new(x3, y3), ECPoint::new(x1, y1))
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
    fn test_curve_native_add_gadget_constraints() {
        let gadget = CurveNativeAddGadget::<PallasParameters>::new();

        let mut env = ConstraintEnv::<Fp>::new();

        // Create input
        let input = {
            let x1_pos = env.allocate();
            let x1 = env.read_position(x1_pos);
            let y1_pos = env.allocate();
            let y1 = env.read_position(y1_pos);
            let x2_pos = env.allocate();
            let x2 = env.read_position(x2_pos);
            let y2_pos = env.allocate();
            let y2 = env.read_position(y2_pos);
            ECPointPair::from_coords(x1, y1, x2, y2)
        };

        let _ = gadget.synthesize(&mut env, input);

        // CurveNativeAddGadget has 3 constraints:
        // 1. is_same * (1 - is_same) = 0 (boolean check, degree 2)
        // 2. (1 - is_same) * (λ * dx - dy) = 0 (different point, degree 3)
        // 3. is_same * (λ * 2y1 - 3x1² - a) = 0 (doubling, degree 3)
        assert_eq!(
            env.num_constraints(),
            3,
            "CurveNativeAddGadget should have 3 constraints"
        );

        // Max degree is 3 (from the is_same * (λ*2y1 - 3x1² - a) constraint)
        assert_eq!(env.max_degree(), 3, "Max degree should be 3");

        // 2 witness allocations: is_same, lambda (plus 4 for inputs)
        assert_eq!(
            env.num_witness_allocations(),
            6,
            "Should have 6 allocations (4 inputs + 2 witnesses)"
        );

        env.check_degrees()
            .expect("All constraints should have degree <= MAX_DEGREE");
    }

    #[test]
    fn test_curve_native_add_gadget_selector() {
        assert_eq!(
            <CurveNativeAddGadget<PallasParameters> as TypedGadget<Fp>>::Selector::GADGET,
            crate::column::Gadget::EllipticCurveAddition
        );
        assert_eq!(
            <CurveNativeAddGadget<PallasParameters> as TypedGadget<Fp>>::Selector::INDEX,
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
    fn test_curve_native_add_gadget_different_points() {
        let gadget = CurveNativeAddGadget::<PallasParameters>::new();

        let g = Pallas::generator();
        let g2: Pallas = (Pallas::generator() + Pallas::generator()).into();

        let input = ECPointPair::new(ECPoint::new(g.x, g.y), ECPoint::new(g2.x, g2.y));
        let output = gadget.output(&input);

        let g3: Pallas = (Pallas::generator() + Pallas::generator() + Pallas::generator()).into();

        // output.p1 is the result, output.p2 is the original P1
        assert_eq!(output.p1.x, g3.x, "X coordinate of 3G should match");
        assert_eq!(output.p1.y, g3.y, "Y coordinate of 3G should match");
        assert_eq!(output.p2.x, g.x, "Original X should be preserved");
        assert_eq!(output.p2.y, g.y, "Original Y should be preserved");
    }

    #[test]
    fn test_curve_native_add_gadget_random_points() {
        let seed: u64 = rand::random();
        println!("test_curve_native_add_gadget_random_points seed: {seed}");
        let mut rng = rand::rngs::StdRng::seed_from_u64(seed);

        let gadget = CurveNativeAddGadget::<PallasParameters>::new();

        // Generate two different random points
        let s1: u64 = rng.gen_range(1..1_000_000);
        let s2: u64 = rng.gen_range(1_000_001..2_000_000); // Ensure different from s1

        let p1: Pallas = Pallas::generator().mul_bigint([s1]).into();
        let p2: Pallas = Pallas::generator().mul_bigint([s2]).into();

        let input = ECPointPair::new(ECPoint::new(p1.x, p1.y), ECPoint::new(p2.x, p2.y));
        let output = gadget.output(&input);

        // Verify against arkworks
        let sum: Pallas = (p1 + p2).into();

        assert_eq!(output.p1.x, sum.x, "X coordinate should match arkworks");
        assert_eq!(output.p1.y, sum.y, "Y coordinate should match arkworks");
    }

    #[test]
    fn test_curve_native_add_gadget_same_point_doubles() {
        let gadget = CurveNativeAddGadget::<PallasParameters>::new();

        let g = Pallas::generator();
        let input = ECPointPair::new(ECPoint::new(g.x, g.y), ECPoint::new(g.x, g.y));
        let output = gadget.output(&input);

        let g2: Pallas = (Pallas::generator() + Pallas::generator()).into();

        assert_eq!(output.p1.x, g2.x, "X coordinate of 2G should match");
        assert_eq!(output.p1.y, g2.y, "Y coordinate of 2G should match");
    }

    #[test]
    fn test_curve_native_add_gadget_chaining() {
        let gadget = CurveNativeAddGadget::<PallasParameters>::new();

        let g = Pallas::generator();
        let g2: Pallas = (Pallas::generator() + Pallas::generator()).into();

        // First addition: G + 2G = 3G
        let input1 = ECPointPair::new(ECPoint::new(g.x, g.y), ECPoint::new(g2.x, g2.y));
        let result1 = gadget.output(&input1);

        // Chain: 3G + G = 4G (using result as p1 and original as p2)
        let input2 = ECPointPair::new(result1.p1.clone(), result1.p2);
        let result2 = gadget.output(&input2);

        let g4: Pallas =
            (Pallas::generator() + Pallas::generator() + Pallas::generator() + Pallas::generator())
                .into();

        assert_eq!(result2.p1.x, g4.x, "X coordinate of 4G should match");
        assert_eq!(result2.p1.y, g4.y, "Y coordinate of 4G should match");
    }
}
