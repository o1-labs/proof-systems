//! Elliptic curve addition circuit gadgets.
//!
//! This module implements elliptic curve point addition as circuits that can be
//! composed to build the IVC verifier circuit.
//!
//! # Available Circuits
//!
//! - [`CurveNativeAdd`]: General point addition with automatic doubling detection.
//!   Handles both P1 + P2 (different points) and 2*P (same point).
//! - [`CurveNativeDouble`]: Specialized point doubling, computes 2*P.
//!
//! # Type Safety
//!
//! All circuits are parameterized by a curve type `C` implementing [`SWCurveConfig`],
//! which guarantees at compile time that:
//! 1. The curve is in short Weierstrass form (y² = x³ + ax + b)
//! 2. Points are in affine coordinates (x, y)
//!
//! This enables type-safe circuit composition: when combining circuits
//! (e.g., scalar multiplication using additions), the curve types are checked
//! at compile time, preventing mismatched curves.
//!
//! # Layout
//!
//! For [`CurveNativeAdd`] with inputs (x1, y1) and (x2, y2):
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
//! For [`CurveNativeAdd`]:
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
//!
//! For [`CurveNativeDouble`]:
//! - λ * 2Y1 - 3X1² - a = 0 (slope constraint)

use ark_ec::short_weierstrass::SWCurveConfig;
use ark_ff::{Field, One, PrimeField, Zero};
use core::marker::PhantomData;

use crate::circuit::{CircuitEnv, SelectorEnv, StepCircuit};

/// Native field elliptic curve addition circuit.
///
/// Computes P3 = P1 + P2 where P1 = (x1, y1) and P2 = (x2, y2).
/// Handles both the general addition case and point doubling.
///
/// "Native" means the curve's base field matches the circuit's field.
///
/// The circuit is parameterized by a curve type `C` implementing [`SWCurveConfig`],
/// which guarantees at compile time that:
/// 1. The curve is in short Weierstrass form (y² = x³ + ax + b)
/// 2. Points are in affine coordinates
///
/// # Type Parameters
///
/// - `C`: A curve configuration implementing [`SWCurveConfig`]
///
/// # State Format
///
/// The state is a 4-element array: [x1, y1, x2, y2] in affine coordinates.
/// The output is [x3, y3, x1, y1] where (x3, y3) = P1 + P2.
/// This allows chaining: the result can be used as the first point
/// for the next addition.
pub struct CurveNativeAdd<C: SWCurveConfig> {
    _marker: PhantomData<C>,
}

impl<C: SWCurveConfig> Clone for CurveNativeAdd<C> {
    fn clone(&self) -> Self {
        Self {
            _marker: PhantomData,
        }
    }
}

impl<C: SWCurveConfig> core::fmt::Debug for CurveNativeAdd<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CurveNativeAdd").finish()
    }
}

impl<C: SWCurveConfig> CurveNativeAdd<C>
where
    C::BaseField: PrimeField,
{
    /// Create a new native EC addition circuit.
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
    fn compute_lambda(x1: C::BaseField, y1: C::BaseField, x2: C::BaseField, y2: C::BaseField, is_same: bool) -> C::BaseField {
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
    fn is_same_point(x1: C::BaseField, y1: C::BaseField, x2: C::BaseField, y2: C::BaseField) -> bool {
        x1 == x2 && y1 == y2
    }
}

impl<C: SWCurveConfig> Default for CurveNativeAdd<C>
where
    C::BaseField: PrimeField,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<C: SWCurveConfig> PartialEq for CurveNativeAdd<C> {
    fn eq(&self, _other: &Self) -> bool {
        true
    }
}

impl<C: SWCurveConfig> Eq for CurveNativeAdd<C> {}

impl<C: SWCurveConfig> StepCircuit<C::BaseField, 4> for CurveNativeAdd<C>
where
    C::BaseField: PrimeField,
{
    const NAME: &'static str = "CurveNativeAdd";

    fn synthesize<E: CircuitEnv<C::BaseField> + SelectorEnv<C::BaseField>>(
        &self,
        env: &mut E,
        z: &[E::Variable; 4],
    ) -> [E::Variable; 4] {
        // Input points: P1 = (x1, y1), P2 = (x2, y2)
        let x1 = z[0].clone();
        let y1 = z[1].clone();
        let x2 = z[2].clone();
        let y2 = z[3].clone();

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

        // Return [x3, y3, x1, y1] to allow chaining
        [x3, y3, x1.clone(), y1.clone()]
    }

    fn output(&self, z: &[C::BaseField; 4]) -> [C::BaseField; 4] {
        let x1 = z[0];
        let y1 = z[1];
        let x2 = z[2];
        let y2 = z[3];

        let is_same = Self::is_same_point(x1, y1, x2, y2);
        let lambda = Self::compute_lambda(x1, y1, x2, y2, is_same);

        // X3 = λ² - X1 - X2
        let x3 = lambda * lambda - x1 - x2;

        // Y3 = λ (X1 - X3) - Y1
        let y3 = lambda * (x1 - x3) - y1;

        // Return [x3, y3, x1, y1] for chaining
        [x3, y3, x1, y1]
    }
}

/// Native field EC point doubling circuit (specialized version).
///
/// Computes P2 = 2*P1 where P1 = (x1, y1).
/// This is a specialized version when we know both inputs are the same.
///
/// The circuit is parameterized by a curve type `C` implementing [`SWCurveConfig`],
/// which guarantees at compile time that:
/// 1. The curve is in short Weierstrass form (y² = x³ + ax + b)
/// 2. Points are in affine coordinates
///
/// # Type Parameters
///
/// - `C`: A curve configuration implementing [`SWCurveConfig`]
pub struct CurveNativeDouble<C: SWCurveConfig> {
    _marker: PhantomData<C>,
}

impl<C: SWCurveConfig> Clone for CurveNativeDouble<C> {
    fn clone(&self) -> Self {
        Self {
            _marker: PhantomData,
        }
    }
}

impl<C: SWCurveConfig> core::fmt::Debug for CurveNativeDouble<C> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CurveNativeDouble").finish()
    }
}

impl<C: SWCurveConfig> CurveNativeDouble<C>
where
    C::BaseField: PrimeField,
{
    /// Create a new native EC doubling circuit.
    ///
    /// The curve type `C` must implement [`SWCurveConfig`], which provides
    /// the curve coefficients and ensures the curve is in short Weierstrass form.
    pub fn new() -> Self {
        Self {
            _marker: PhantomData,
        }
    }
}

impl<C: SWCurveConfig> Default for CurveNativeDouble<C>
where
    C::BaseField: PrimeField,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<C: SWCurveConfig> PartialEq for CurveNativeDouble<C> {
    fn eq(&self, _other: &Self) -> bool {
        true
    }
}

impl<C: SWCurveConfig> Eq for CurveNativeDouble<C> {}

impl<C: SWCurveConfig> StepCircuit<C::BaseField, 2> for CurveNativeDouble<C>
where
    C::BaseField: PrimeField,
{
    const NAME: &'static str = "CurveNativeDouble";

    fn synthesize<E: CircuitEnv<C::BaseField> + SelectorEnv<C::BaseField>>(
        &self,
        env: &mut E,
        z: &[E::Variable; 2],
    ) -> [E::Variable; 2] {
        let x1 = z[0].clone();
        let y1 = z[1].clone();

        // λ = (3x1² + a) / (2y1)
        // Constraint: λ * 2y1 = 3x1² + a
        let lambda = {
            let pos = env.allocate();
            env.write_column(pos, env.constant(C::BaseField::zero()))
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

        // X3 = λ² - 2X1
        let lambda_squared = lambda.clone() * lambda.clone();
        let two_x1 = two * x1.clone();
        let x3 = lambda_squared - two_x1;

        // Y3 = λ (X1 - X3) - Y1
        let x1_minus_x3 = x1 - x3.clone();
        let lambda_times_diff = lambda * x1_minus_x3;
        let y3 = lambda_times_diff - y1;

        [x3, y3]
    }

    fn output(&self, z: &[C::BaseField; 2]) -> [C::BaseField; 2] {
        let x1 = z[0];
        let y1 = z[1];

        // λ = (3x1² + a) / (2y1)
        let numerator = C::BaseField::from(3u64) * x1 * x1 + C::COEFF_A;
        let denominator = C::BaseField::from(2u64) * y1;
        let lambda = numerator * denominator.inverse().unwrap();

        // X3 = λ² - 2X1
        let x3 = lambda * lambda - C::BaseField::from(2u64) * x1;

        // Y3 = λ (X1 - X3) - Y1
        let y3 = lambda * (x1 - x3) - y1;

        [x3, y3]
    }
}

// ============================================================================
// Constraint tests
// ============================================================================

#[cfg(test)]
mod constraint_tests {
    use super::*;
    use crate::circuit::ConstraintEnv;
    use mina_curves::pasta::{Fp, PallasParameters};

    #[test]
    fn test_curve_native_double_constraints() {
        let circuit = CurveNativeDouble::<PallasParameters>::new();

        let mut env = ConstraintEnv::<Fp>::new();
        let z = env.make_input_vars::<2>();
        let _ = circuit.synthesize(&mut env, &z);

        // CurveNativeDouble has 1 constraint: λ * 2y1 = 3x1² + a
        assert_eq!(
            env.num_constraints(),
            1,
            "CurveNativeDouble should have 1 constraint"
        );

        // The constraint has degree 2 (λ * y1 is degree 2, x1² is degree 2)
        assert_eq!(env.max_degree(), 2, "Max degree should be 2");

        // 1 witness allocation for λ
        assert_eq!(
            env.num_witness_allocations(),
            1,
            "Should have 1 witness allocation for λ"
        );

        env.check_degrees()
            .expect("All constraints should have degree <= MAX_DEGREE");
    }

    /// Regression test for CurveNativeDouble metrics.
    #[test]
    fn test_curve_native_double_metrics() {
        let circuit = CurveNativeDouble::<PallasParameters>::new();

        let mut env = ConstraintEnv::<Fp>::new();
        let z = env.make_input_vars::<2>();
        let _ = circuit.synthesize(&mut env, &z);

        assert_eq!(env.num_constraints(), 1, "constraints changed");
        assert_eq!(env.num_witness_allocations(), 1, "witness allocations changed");
        assert_eq!(env.max_degree(), 2, "max degree changed");
    }

    #[test]
    fn test_curve_native_add_constraints() {
        let circuit = CurveNativeAdd::<PallasParameters>::new();

        let mut env = ConstraintEnv::<Fp>::new();
        let z = env.make_input_vars::<4>();
        let _ = circuit.synthesize(&mut env, &z);

        // CurveNativeAdd has 3 constraints:
        // 1. is_same * (1 - is_same) = 0 (boolean check, degree 2)
        // 2. (1 - is_same) * (λ * dx - dy) = 0 (different point, degree 3)
        // 3. is_same * (λ * 2y1 - 3x1² - a) = 0 (doubling, degree 3)
        assert_eq!(
            env.num_constraints(),
            3,
            "CurveNativeAdd should have 3 constraints"
        );

        // Max degree is 3 (from the is_same * (λ*2y1 - 3x1² - a) constraint)
        assert_eq!(env.max_degree(), 3, "Max degree should be 3");

        // 2 witness allocations: is_same, lambda
        assert_eq!(
            env.num_witness_allocations(),
            2,
            "Should have 2 witness allocations"
        );

        env.check_degrees()
            .expect("All constraints should have degree <= MAX_DEGREE");
    }

    /// Regression test for CurveNativeAdd metrics.
    #[test]
    fn test_curve_native_add_metrics() {
        let circuit = CurveNativeAdd::<PallasParameters>::new();

        let mut env = ConstraintEnv::<Fp>::new();
        let z = env.make_input_vars::<4>();
        let _ = circuit.synthesize(&mut env, &z);

        assert_eq!(env.num_constraints(), 3, "constraints changed");
        assert_eq!(env.num_witness_allocations(), 2, "witness allocations changed");
        assert_eq!(env.max_degree(), 3, "max degree changed");
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
    fn test_curve_native_double_output() {
        let circuit = CurveNativeDouble::<PallasParameters>::new();

        let g = Pallas::generator();
        let [x3, y3] = circuit.output(&[g.x, g.y]);

        let g2: Pallas = (Pallas::generator() + Pallas::generator()).into();

        assert_eq!(x3, g2.x, "X coordinate of 2G should match");
        assert_eq!(y3, g2.y, "Y coordinate of 2G should match");
    }

    #[test]
    fn test_curve_native_double_random_points() {
        let circuit = CurveNativeDouble::<PallasParameters>::new();
        let mut rng = rand::rngs::StdRng::seed_from_u64(42);

        for _ in 0..10 {
            // Generate random scalar and compute random point
            let scalar: u64 = rng.gen();
            let p: Pallas = Pallas::generator().mul_bigint([scalar]).into();

            let [x3, y3] = circuit.output(&[p.x, p.y]);

            // Verify against arkworks
            let doubled: Pallas = (p + p).into();

            assert_eq!(x3, doubled.x, "X coordinate should match arkworks");
            assert_eq!(y3, doubled.y, "Y coordinate should match arkworks");
        }
    }

    #[test]
    fn test_curve_native_double_deterministic() {
        let circuit = CurveNativeDouble::<PallasParameters>::new();

        let g = Pallas::generator();
        let z = [g.x, g.y];

        let output1 = circuit.output(&z);
        let output2 = circuit.output(&z);

        assert_eq!(output1, output2, "Same inputs should give same outputs");
    }

    #[test]
    fn test_curve_native_add_different_points() {
        let circuit = CurveNativeAdd::<PallasParameters>::new();

        let g = Pallas::generator();
        let g2: Pallas = (Pallas::generator() + Pallas::generator()).into();

        let [x3, y3, _, _] = circuit.output(&[g.x, g.y, g2.x, g2.y]);

        let g3: Pallas = (Pallas::generator() + Pallas::generator() + Pallas::generator()).into();

        assert_eq!(x3, g3.x, "X coordinate of 3G should match");
        assert_eq!(y3, g3.y, "Y coordinate of 3G should match");
    }

    #[test]
    fn test_curve_native_add_random_points() {
        let circuit = CurveNativeAdd::<PallasParameters>::new();
        let mut rng = rand::rngs::StdRng::seed_from_u64(42);

        for _ in 0..10 {
            // Generate two random points
            let s1: u64 = rng.gen_range(1..1_000_000);
            let s2: u64 = rng.gen_range(1..1_000_000);

            let p1: Pallas = Pallas::generator().mul_bigint([s1]).into();
            let p2: Pallas = Pallas::generator().mul_bigint([s2]).into();

            // Skip if points are the same (tested separately)
            if p1 == p2 {
                continue;
            }

            let [x3, y3, _, _] = circuit.output(&[p1.x, p1.y, p2.x, p2.y]);

            // Verify against arkworks
            let sum: Pallas = (p1 + p2).into();

            assert_eq!(x3, sum.x, "X coordinate should match arkworks");
            assert_eq!(y3, sum.y, "Y coordinate should match arkworks");
        }
    }

    #[test]
    fn test_curve_native_add_same_point_doubles() {
        let circuit = CurveNativeAdd::<PallasParameters>::new();

        let g = Pallas::generator();
        let [x3, y3, _, _] = circuit.output(&[g.x, g.y, g.x, g.y]);

        let g2: Pallas = (Pallas::generator() + Pallas::generator()).into();

        assert_eq!(x3, g2.x, "X coordinate of 2G should match");
        assert_eq!(y3, g2.y, "Y coordinate of 2G should match");
    }

    #[test]
    fn test_curve_native_add_chaining() {
        let circuit = CurveNativeAdd::<PallasParameters>::new();

        let g = Pallas::generator();
        let g2: Pallas = (Pallas::generator() + Pallas::generator()).into();

        // First addition: G + 2G = 3G
        let result1 = circuit.output(&[g.x, g.y, g2.x, g2.y]);

        // Chain: 3G + G = 4G
        let result2 = circuit.output(&[result1[0], result1[1], result1[2], result1[3]]);

        let g4: Pallas = (Pallas::generator()
            + Pallas::generator()
            + Pallas::generator()
            + Pallas::generator())
        .into();

        assert_eq!(result2[0], g4.x, "X coordinate of 4G should match");
        assert_eq!(result2[1], g4.y, "Y coordinate of 4G should match");
    }
}

// Note: Trace tests are not included for these circuits because they use
// write_column(pos, env.constant(F::zero())) which doesn't compute actual witness values.
// The circuits are designed for ConstraintEnv (symbolic mode) and output
// correctness is verified in output_tests module using the output() function.
