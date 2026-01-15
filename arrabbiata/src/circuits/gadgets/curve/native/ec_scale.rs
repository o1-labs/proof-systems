//! Native field elliptic curve scalar multiplication circuit gadgets.
//!
//! This module implements elliptic curve scalar multiplication using the
//! double-and-add algorithm. Each step processes one bit of the scalar.
//!
//! # Available Gadgets
//!
//! - [`CurveNativeScalarMulStepGadget`]: Single step of scalar multiplication (one bit).
//!   Use this when you need fine-grained control over the multiplication.
//! - [`CurveNativeScalarMulGadget`]: Full scalar multiplication for `num_bits` bits.
//!   Chains multiple steps and handles the final subtraction.
//!
//! # Type Safety
//!
//! All gadgets are parameterized by a curve type `C` implementing [`SWCurveConfig`],
//! which guarantees at compile time that:
//! 1. The curve is in short Weierstrass form (y² = x³ + ax + b)
//! 2. Points are in affine coordinates (x, y)
//!
//! This enables type-safe circuit composition: when combining gadgets
//! (e.g., Schnorr signature using scalar multiplication), the curve types are checked
//! at compile time, preventing mismatched curves.
//!
//! # Algorithm
//!
//! The double-and-add algorithm computes `[k]P` for scalar `k` and point `P`:
//!
//! ```text
//! res = starting_point  (non-zero to avoid point at infinity)
//! tmp = P
//! for i in 0..num_bits:
//!   if k[i] == 1:
//!     res = res + tmp
//!   tmp = 2 * tmp
//! res = res - starting_point  (remove the initial offset)
//! ```
//!
//! # Avoiding the Point at Infinity
//!
//! A naive implementation would initialize `res = O` (the identity/point at
//! infinity). However, handling the point at infinity in affine coordinates
//! requires special case logic that adds complexity to the circuit.
//!
//! Instead, we initialize `res = P` (the base point itself) and subtract `P`
//! at the end:
//! - After the loop: `res = P + [k]P = [k+1]P`
//! - After subtraction: `res = [k+1]P - P = [k]P`
//!
//! This approach keeps all intermediate values as valid affine points,
//! avoiding the need to handle the point at infinity.
//!
//! # Layout
//!
//! For a single bit step ([`CurveNativeScalarMulStepGadget`]):
//!
//! ```text
//! | C1   |   C2   |    C3    |    C4    |  C5  |  C6 |   C7   |   C8   | C9 | C10 |
//! | --   | -----  | -------- | -------- | ---- | --- | ------ | ------ | -- | --- |
//! | o_x  |  o_y   | tmp_x    | tmp_y    | r_i  | λ   | sum_x  | sum_y  | λ' | bit |
//! | o'_x |  o'_y  | tmp'_x   | tmp'_y   | r'   |
//! ```
//!
//! Where:
//! - (o_x, o_y): Current accumulator in affine coordinates
//! - (tmp_x, tmp_y): Current doubled point in affine coordinates
//! - r_i: Remaining scalar bits
//! - λ: Slope for res + tmp addition
//! - (sum_x, sum_y): Result of res + tmp
//! - λ': Slope for tmp doubling
//! - bit: Current bit being processed
//! - Primed values: Next row values

use ark_ec::short_weierstrass::SWCurveConfig;
use ark_ff::{Field, One, PrimeField, Zero};
use core::marker::PhantomData;

use crate::{
    circuit::{CircuitEnv, SelectorEnv},
    circuits::{
        gadget::{ECPoint, ECScalarMulInput, ECScalarMulState, Position, Row, TypedGadget},
        selector::QECScale,
    },
};

// ============================================================================
// CurveNativeScalarMulStepGadget - Single step of scalar multiplication
// ============================================================================

// Position constants for CurveNativeScalarMulStepGadget
// Layout (current row): | o_x | o_y | tmp_x | tmp_y | r_i | λ | sum_x | sum_y | λ' | bit |
//                       |  0  |  1  |   2   |   3   |  4  | 5 |   6   |   7   |  8 |  9  |
// Layout (next row):    | o'_x | o'_y | tmp'_x | tmp'_y | r' |
//                       |  0   |  1   |   2    |   3    |  4 |
const EC_SCALE_STEP_INPUT_POSITIONS: &[Position] = &[
    Position {
        col: 0,
        row: Row::Curr,
    }, // o_x (res_x)
    Position {
        col: 1,
        row: Row::Curr,
    }, // o_y (res_y)
    Position {
        col: 2,
        row: Row::Curr,
    }, // tmp_x
    Position {
        col: 3,
        row: Row::Curr,
    }, // tmp_y
    Position {
        col: 4,
        row: Row::Curr,
    }, // r_i (scalar)
];
const EC_SCALE_STEP_OUTPUT_POSITIONS: &[Position] = &[
    Position {
        col: 0,
        row: Row::Next,
    }, // o'_x (next res_x)
    Position {
        col: 1,
        row: Row::Next,
    }, // o'_y (next res_y)
    Position {
        col: 2,
        row: Row::Next,
    }, // tmp'_x (next tmp_x)
    Position {
        col: 3,
        row: Row::Next,
    }, // tmp'_y (next tmp_y)
    Position {
        col: 4,
        row: Row::Next,
    }, // r' (next scalar)
];

/// Single step of native field EC scalar multiplication (processes one bit).
///
/// This gadget processes one bit of the scalar using double-and-add.
/// Chain multiple instances to compute the full scalar multiplication.
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
/// Input: `ECScalarMulState<V>` containing (res, tmp, scalar)
/// - res: Current accumulator point
/// - tmp: Current doubled point
/// - scalar: Remaining scalar value
///
/// Output: Same format with updated values after one bit step.
pub struct CurveNativeScalarMulStepGadget<C: SWCurveConfig> {
    _marker: PhantomData<C>,
}

impl<C: SWCurveConfig> Clone for CurveNativeScalarMulStepGadget<C> {
    fn clone(&self) -> Self {
        Self {
            _marker: PhantomData,
        }
    }
}

impl<C: SWCurveConfig> core::fmt::Debug for CurveNativeScalarMulStepGadget<C> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CurveNativeScalarMulStepGadget").finish()
    }
}

impl<C: SWCurveConfig> CurveNativeScalarMulStepGadget<C>
where
    C::BaseField: PrimeField,
{
    /// Create a new native EC scaling step gadget.
    ///
    /// The curve type `C` must implement [`SWCurveConfig`], which provides
    /// the curve coefficients and ensures the curve is in short Weierstrass form.
    pub fn new() -> Self {
        Self {
            _marker: PhantomData,
        }
    }

    /// Compute λ for point addition (different points).
    fn compute_lambda_add(
        x1: C::BaseField,
        y1: C::BaseField,
        x2: C::BaseField,
        y2: C::BaseField,
    ) -> C::BaseField {
        let numerator = y1 - y2;
        let denominator = x1 - x2;
        numerator * denominator.inverse().unwrap()
    }

    /// Compute λ for point doubling.
    fn compute_lambda_double(x: C::BaseField, y: C::BaseField) -> C::BaseField {
        let numerator = C::BaseField::from(3u64) * x * x + C::COEFF_A;
        let denominator = C::BaseField::from(2u64) * y;
        numerator * denominator.inverse().unwrap()
    }
}

impl<C: SWCurveConfig> Default for CurveNativeScalarMulStepGadget<C>
where
    C::BaseField: PrimeField,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<C: SWCurveConfig> PartialEq for CurveNativeScalarMulStepGadget<C> {
    fn eq(&self, _other: &Self) -> bool {
        true
    }
}

impl<C: SWCurveConfig> Eq for CurveNativeScalarMulStepGadget<C> {}

impl<C: SWCurveConfig> TypedGadget<C::BaseField> for CurveNativeScalarMulStepGadget<C>
where
    C::BaseField: PrimeField,
{
    type Selector = QECScale;
    type Input<V: Clone> = ECScalarMulState<V>;
    type Output<V: Clone> = ECScalarMulState<V>;

    const NAME: &'static str = "ec-scalar-mul-step";
    const DESCRIPTION: &'static str = "Single step of EC scalar multiplication";
    const ARITY: usize = 4;
    const ROWS: usize = 1;

    fn input_positions() -> &'static [Position] {
        EC_SCALE_STEP_INPUT_POSITIONS
    }

    fn output_positions() -> &'static [Position] {
        EC_SCALE_STEP_OUTPUT_POSITIONS
    }

    fn synthesize<E: CircuitEnv<C::BaseField> + SelectorEnv<C::BaseField>>(
        &self,
        env: &mut E,
        input: Self::Input<E::Variable>,
    ) -> Self::Output<E::Variable> {
        // Layout (from module docs):
        // | C1   |  C2  |  C3   |  C4   | C5  | C6 |  C7   |  C8   | C9 | C10 |
        // | o_x  | o_y  | tmp_x | tmp_y | r_i | λ  | sum_x | sum_y | λ' | bit |
        // | o'_x | o'_y | tmp'_x| tmp'_y| r'  |
        //
        // Inputs on current row (C1-C5)
        let o_x = input.res.x;
        let o_y = input.res.y;
        let tmp_x = input.tmp.x;
        let tmp_y = input.tmp.y;
        let r_i = input.scalar;

        // Try to extract concrete values for witness computation
        let witness_vals = match (
            env.try_as_field(&o_x),
            env.try_as_field(&o_y),
            env.try_as_field(&tmp_x),
            env.try_as_field(&tmp_y),
            env.try_as_field(&r_i),
        ) {
            (Some(o_x_f), Some(o_y_f), Some(tmp_x_f), Some(tmp_y_f), Some(r_i_f)) => {
                // In witness mode: compute actual values

                // Extract bit from scalar
                let scalar_bigint: num_bigint::BigUint = r_i_f.into();
                let bit_bool = scalar_bigint.bit(0);
                let bit_f = if bit_bool {
                    C::BaseField::one()
                } else {
                    C::BaseField::zero()
                };
                let next_scalar_bigint = &scalar_bigint >> 1;
                let r_next_f = C::BaseField::from(next_scalar_bigint);

                // Check if res == tmp (same point)
                let is_same = o_x_f == tmp_x_f && o_y_f == tmp_y_f;

                // Compute λ for addition (or doubling if same point)
                // and compute sum = o + tmp
                let (lambda_add_f, sum_x_f, sum_y_f) = if is_same {
                    // Use doubling formula: λ = (3x² + a) / (2y)
                    let lambda = Self::compute_lambda_double(o_x_f, o_y_f);
                    let x3 = lambda * lambda - C::BaseField::from(2u64) * o_x_f;
                    let y3 = lambda * (o_x_f - x3) - o_y_f;
                    (lambda, x3, y3)
                } else {
                    // Use addition formula: λ = (y1 - y2) / (x1 - x2)
                    let lambda = Self::compute_lambda_add(o_x_f, o_y_f, tmp_x_f, tmp_y_f);
                    let x3 = lambda * lambda - o_x_f - tmp_x_f;
                    let y3 = lambda * (o_x_f - x3) - o_y_f;
                    (lambda, x3, y3)
                };

                // Compute λ' for doubling: λ' = (3*tmp_x² + a) / (2*tmp_y)
                let lambda_double_f = Self::compute_lambda_double(tmp_x_f, tmp_y_f);

                // Compute doubled tmp
                let tmp_x_next_f =
                    lambda_double_f * lambda_double_f - C::BaseField::from(2u64) * tmp_x_f;
                let tmp_y_next_f = lambda_double_f * (tmp_x_f - tmp_x_next_f) - tmp_y_f;

                // Conditional select for next res
                let (o_x_next_f, o_y_next_f) = if bit_bool {
                    (sum_x_f, sum_y_f)
                } else {
                    (o_x_f, o_y_f)
                };

                Some((
                    lambda_add_f,
                    sum_x_f,
                    sum_y_f,
                    lambda_double_f,
                    bit_f,
                    o_x_next_f,
                    o_y_next_f,
                    tmp_x_next_f,
                    tmp_y_next_f,
                    r_next_f,
                ))
            }
            _ => None,
        };

        // Get witness values or use placeholders
        let (
            lambda_add_val,
            sum_x_val,
            sum_y_val,
            lambda_double_val,
            bit_val,
            o_x_next_val,
            o_y_next_val,
            tmp_x_next_val,
            tmp_y_next_val,
            r_next_val,
        ) = witness_vals.unwrap_or((
            C::BaseField::zero(),
            C::BaseField::zero(),
            C::BaseField::zero(),
            C::BaseField::zero(),
            C::BaseField::zero(),
            C::BaseField::zero(),
            C::BaseField::zero(),
            C::BaseField::zero(),
            C::BaseField::zero(),
            C::BaseField::zero(),
        ));

        // Constants
        let one = env.constant(C::BaseField::one());
        let two = env.constant(C::BaseField::from(2u64));
        let three = env.constant(C::BaseField::from(3u64));
        let a_const = env.constant(C::COEFF_A);

        // Allocate intermediate witnesses on current row (C6-C10)
        // C6: λ (slope for addition)
        let lambda_add = {
            let pos = env.allocate();
            env.write_column(pos, env.constant(lambda_add_val))
        };
        // C7: sum_x (result of o + tmp addition)
        let sum_x = {
            let pos = env.allocate();
            env.write_column(pos, env.constant(sum_x_val))
        };
        // C8: sum_y
        let sum_y = {
            let pos = env.allocate();
            env.write_column(pos, env.constant(sum_y_val))
        };
        // C9: λ' (slope for doubling)
        let lambda_double = {
            let pos = env.allocate();
            env.write_column(pos, env.constant(lambda_double_val))
        };
        // C10: bit (current scalar bit)
        let bit = {
            let pos = env.allocate();
            env.write_column(pos, env.constant(bit_val))
        };

        // Constraint 1: bit is boolean
        // bit * (1 - bit) = 0
        let one_minus_bit = one.clone() - bit.clone();
        let bit_boolean = bit.clone() * one_minus_bit.clone();
        env.assert_zero_named("bit_boolean", &bit_boolean);

        // Constraint 2: λ * (o_x - tmp_x) = o_y - tmp_y (addition slope)
        let o_x_minus_tmp_x = o_x.clone() - tmp_x.clone();
        let o_y_minus_tmp_y = o_y.clone() - tmp_y.clone();
        let lambda_dx = lambda_add.clone() * o_x_minus_tmp_x;
        let add_slope_check = lambda_dx - o_y_minus_tmp_y;
        env.assert_zero_named("add_slope", &add_slope_check);

        // Constraint 3: sum_x = λ² - o_x - tmp_x
        let lambda_add_sq = lambda_add.clone() * lambda_add.clone();
        let sum_x_expected = lambda_add_sq.clone() - o_x.clone() - tmp_x.clone();
        let sum_x_check = sum_x.clone() - sum_x_expected;
        env.assert_zero_named("sum_x", &sum_x_check);

        // Constraint 4: sum_y = λ * (o_x - sum_x) - o_y
        let o_x_minus_sum_x = o_x.clone() - sum_x.clone();
        let lambda_diff = lambda_add * o_x_minus_sum_x;
        let sum_y_expected = lambda_diff - o_y.clone();
        let sum_y_check = sum_y.clone() - sum_y_expected;
        env.assert_zero_named("sum_y", &sum_y_check);

        // Constraint 5: λ' * 2*tmp_y = 3*tmp_x² + a (doubling slope)
        let tmp_y_times_2 = two.clone() * tmp_y.clone();
        let lambda_double_2y = lambda_double.clone() * tmp_y_times_2;
        let tmp_x_sq = tmp_x.clone() * tmp_x.clone();
        let three_tmp_x_sq = three * tmp_x_sq;
        let double_slope_rhs = three_tmp_x_sq + a_const;
        let double_slope_check = lambda_double_2y - double_slope_rhs;
        env.assert_zero_named("double_slope", &double_slope_check);

        // Compute outputs symbolically
        // o'_x = bit * sum_x + (1 - bit) * o_x (conditional select)
        let bit_sum_x = bit.clone() * sum_x;
        let not_bit_o_x = one_minus_bit.clone() * o_x.clone();
        let o_x_next_expr = bit_sum_x + not_bit_o_x;

        // o'_y = bit * sum_y + (1 - bit) * o_y
        let bit_sum_y = bit.clone() * sum_y;
        let not_bit_o_y = one_minus_bit.clone() * o_y;
        let o_y_next_expr = bit_sum_y + not_bit_o_y;

        // Allocate outputs on next row (C1-C5)
        // We allocate first, then constrain using the witnesses to keep degree low
        let o_x_next = {
            let pos = env.allocate_next_row();
            env.write_column(pos, env.constant(o_x_next_val))
        };
        let o_y_next = {
            let pos = env.allocate_next_row();
            env.write_column(pos, env.constant(o_y_next_val))
        };
        let tmp_x_next = {
            let pos = env.allocate_next_row();
            env.write_column(pos, env.constant(tmp_x_next_val))
        };
        let tmp_y_next = {
            let pos = env.allocate_next_row();
            env.write_column(pos, env.constant(tmp_y_next_val))
        };

        // Constraint 6: o'_x = bit * sum_x + (1 - bit) * o_x
        let o_x_next_check = o_x_next.clone() - o_x_next_expr;
        env.assert_zero_named("o_x_next", &o_x_next_check);

        // Constraint 7: o'_y = bit * sum_y + (1 - bit) * o_y
        let o_y_next_check = o_y_next.clone() - o_y_next_expr;
        env.assert_zero_named("o_y_next", &o_y_next_check);

        // Constraint 8: tmp'_x = λ'² - 2*tmp_x
        // tmp'_x + 2*tmp_x - λ'² = 0
        let lambda_double_sq = lambda_double.clone() * lambda_double.clone();
        let two_tmp_x = two.clone() * tmp_x.clone();
        let tmp_x_next_check = tmp_x_next.clone() + two_tmp_x - lambda_double_sq;
        env.assert_zero_named("tmp_x_next", &tmp_x_next_check);

        // Constraint 9: tmp'_y = λ' * (tmp_x - tmp'_x) - tmp_y
        // tmp'_y + tmp_y - λ' * (tmp_x - tmp'_x) = 0
        // Note: using tmp_x_next (witness) not expression to keep degree at 2
        let tmp_x_minus_tmp_x_next = tmp_x - tmp_x_next.clone();
        let lambda_double_diff = lambda_double * tmp_x_minus_tmp_x_next;
        let tmp_y_next_check = tmp_y_next.clone() + tmp_y - lambda_double_diff;
        env.assert_zero_named("tmp_y_next", &tmp_y_next_check);

        // Constraint 10: r_i = bit + 2 * r' (scalar decomposition)
        // r' is on next row
        let r_next = {
            let pos = env.allocate_next_row();
            env.write_column(pos, env.constant(r_next_val))
        };
        let two_r_next = two * r_next.clone();
        let r_decomp = r_i - bit.clone() - two_r_next;
        env.assert_zero_named("scalar_decomp", &r_decomp);

        ECScalarMulState::new(
            ECPoint::new(o_x_next, o_y_next),
            ECPoint::new(tmp_x_next, tmp_y_next),
            r_next,
        )
    }

    fn output(&self, input: &Self::Input<C::BaseField>) -> Self::Output<C::BaseField> {
        let res_x = input.res.x;
        let res_y = input.res.y;
        let tmp_x = input.tmp.x;
        let tmp_y = input.tmp.y;
        let scalar = input.scalar;

        // Extract lowest bit
        let scalar_bigint: num_bigint::BigUint = scalar.into();
        let bit = scalar_bigint.bit(0);
        let next_scalar_bigint = &scalar_bigint >> 1;
        let next_scalar = C::BaseField::from(next_scalar_bigint);

        // Compute res + tmp (handle case when res == tmp by using doubling)
        let is_same = res_x == tmp_x && res_y == tmp_y;
        let (sum_x, sum_y) = if is_same {
            // Use doubling formula: λ = (3x² + a) / (2y)
            let lambda = Self::compute_lambda_double(res_x, res_y);
            let x3 = lambda * lambda - C::BaseField::from(2u64) * res_x;
            let y3 = lambda * (res_x - x3) - res_y;
            (x3, y3)
        } else {
            // Use addition formula: λ = (y1 - y2) / (x1 - x2)
            let lambda = Self::compute_lambda_add(res_x, res_y, tmp_x, tmp_y);
            let x3 = lambda * lambda - res_x - tmp_x;
            let y3 = lambda * (res_x - x3) - res_y;
            (x3, y3)
        };

        // Conditional select
        let (next_res_x, next_res_y) = if bit { (sum_x, sum_y) } else { (res_x, res_y) };

        // Double tmp
        let lambda_double = Self::compute_lambda_double(tmp_x, tmp_y);
        let next_tmp_x = lambda_double * lambda_double - C::BaseField::from(2u64) * tmp_x;
        let next_tmp_y = lambda_double * (tmp_x - next_tmp_x) - tmp_y;

        ECScalarMulState::new(
            ECPoint::new(next_res_x, next_res_y),
            ECPoint::new(next_tmp_x, next_tmp_y),
            next_scalar,
        )
    }
}

// ============================================================================
// CurveNativeScalarMulGadget - Full scalar multiplication
// ============================================================================

// Position constants for CurveNativeScalarMulGadget
// Input layout: | p_x | p_y | scalar |
//               |  0  |  1  |   2    |
// Output: After num_bits steps + final subtraction, the result is at the end
// The output x3, y3 are allocated after the loop, and scalar is from the state
const EC_SCALE_INPUT_POSITIONS: &[Position] = &[
    Position {
        col: 0,
        row: Row::Curr,
    }, // p_x (base point x)
    Position {
        col: 1,
        row: Row::Curr,
    }, // p_y (base point y)
    Position {
        col: 2,
        row: Row::Curr,
    }, // scalar
];
// Output positions are on the last row after all steps complete
// After the loop: state outputs at cols 0-4, then final subtraction allocates lambda, x3, y3
// - state.res.x at col 0, state.res.y at col 1 (from last step)
// - state.scalar at col 4 (from last step)
// - lambda at col 5, x3 at col 6, y3 at col 7 (final subtraction)
const EC_SCALE_OUTPUT_POSITIONS: &[Position] = &[
    Position {
        col: 6,
        row: Row::Curr,
    }, // x3 (result point x)
    Position {
        col: 7,
        row: Row::Curr,
    }, // y3 (result point y)
    Position {
        col: 4,
        row: Row::Curr,
    }, // remaining scalar (from state)
];

/// Full native field EC scalar multiplication gadget.
///
/// Computes [k]P by chaining `num_bits` steps of the double-and-add algorithm.
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
/// Input: `ECScalarMulInput<V>` containing (P, k)
/// - P: Base point in affine coordinates
/// - k: Scalar
///
/// Output: `ECScalarMulInput<V>` containing (Q, 0)
/// - Q = [k]P in affine coordinates
/// - 0: Remaining scalar (should be 0 if fully consumed)
///
/// # Implementation Details
///
/// To avoid handling the point at infinity, we:
/// 1. Initialize the accumulator to P (the base point)
/// 2. Run the double-and-add loop to compute `[k+1]P`
/// 3. Subtract P at the end to get `[k]P`
///
/// This adds one EC subtraction (implemented as addition with negated point)
/// but eliminates all point-at-infinity checks from the circuit.
pub struct CurveNativeScalarMulGadget<C: SWCurveConfig> {
    /// Number of bits to process (typically 256)
    pub num_bits: usize,
    _marker: PhantomData<C>,
}

impl<C: SWCurveConfig> Clone for CurveNativeScalarMulGadget<C> {
    fn clone(&self) -> Self {
        Self {
            num_bits: self.num_bits,
            _marker: PhantomData,
        }
    }
}

impl<C: SWCurveConfig> core::fmt::Debug for CurveNativeScalarMulGadget<C> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CurveNativeScalarMulGadget")
            .field("num_bits", &self.num_bits)
            .finish()
    }
}

impl<C: SWCurveConfig> CurveNativeScalarMulGadget<C>
where
    C::BaseField: PrimeField,
{
    /// Create a new full native EC scaling gadget.
    ///
    /// The curve type `C` must implement [`SWCurveConfig`], which provides
    /// the curve coefficients and ensures the curve is in short Weierstrass form.
    pub fn new(num_bits: usize) -> Self {
        Self {
            num_bits,
            _marker: PhantomData,
        }
    }

    /// Create with 256 bits (standard for 256-bit scalars).
    pub fn new_standard() -> Self {
        Self::new(256)
    }

    /// Compute λ for point addition (different points).
    fn compute_lambda_add(
        x1: C::BaseField,
        y1: C::BaseField,
        x2: C::BaseField,
        y2: C::BaseField,
    ) -> C::BaseField {
        let numerator = y1 - y2;
        let denominator = x1 - x2;
        numerator * denominator.inverse().unwrap()
    }

    /// Subtract point (x2, y2) from (x1, y1) using affine coordinates.
    /// Subtraction is addition with negated y: (x1, y1) - (x2, y2) = (x1, y1) + (x2, -y2)
    fn subtract_point(
        x1: C::BaseField,
        y1: C::BaseField,
        x2: C::BaseField,
        y2: C::BaseField,
    ) -> (C::BaseField, C::BaseField) {
        // Negate y2 for subtraction
        let neg_y2 = -y2;

        // λ = (y1 - (-y2)) / (x1 - x2) = (y1 + y2) / (x1 - x2)
        let lambda = Self::compute_lambda_add(x1, y1, x2, neg_y2);

        // x3 = λ² - x1 - x2
        let x3 = lambda * lambda - x1 - x2;

        // y3 = λ(x1 - x3) - y1
        let y3 = lambda * (x1 - x3) - y1;

        (x3, y3)
    }
}

impl<C: SWCurveConfig> Default for CurveNativeScalarMulGadget<C>
where
    C::BaseField: PrimeField,
{
    fn default() -> Self {
        Self::new_standard()
    }
}

impl<C: SWCurveConfig> PartialEq for CurveNativeScalarMulGadget<C> {
    fn eq(&self, other: &Self) -> bool {
        self.num_bits == other.num_bits
    }
}

impl<C: SWCurveConfig> Eq for CurveNativeScalarMulGadget<C> {}

impl<C: SWCurveConfig> TypedGadget<C::BaseField> for CurveNativeScalarMulGadget<C>
where
    C::BaseField: PrimeField,
{
    type Selector = QECScale;
    type Input<V: Clone> = ECScalarMulInput<V>;
    type Output<V: Clone> = ECScalarMulInput<V>;

    const NAME: &'static str = "ec-scalar-mul";
    const DESCRIPTION: &'static str = "Elliptic curve scalar multiplication";
    const ARITY: usize = 3;
    const ROWS: usize = 256; // Default, actual depends on num_bits

    fn input_positions() -> &'static [Position] {
        EC_SCALE_INPUT_POSITIONS
    }

    fn output_positions() -> &'static [Position] {
        EC_SCALE_OUTPUT_POSITIONS
    }

    fn synthesize<E: CircuitEnv<C::BaseField> + SelectorEnv<C::BaseField>>(
        &self,
        env: &mut E,
        input: Self::Input<E::Variable>,
    ) -> Self::Output<E::Variable> {
        // Input: [P.x, P.y, scalar]
        // We use P as the initial accumulator to avoid the point at infinity.
        // This computes [k+1]P, and we subtract P at the end to get [k]P.

        let step = CurveNativeScalarMulStepGadget::<C>::new();

        // Initialize: res = P, tmp = P, scalar = k
        let mut state = ECScalarMulState::new(
            input.point.clone(), // res = P
            input.point.clone(), // tmp = P
            input.scalar.clone(),
        );

        // Process each bit: after this, state contains [k+1]P
        for _ in 0..self.num_bits {
            state = step.synthesize(env, state);
            env.next_row(); // Advance to the next row for the next iteration
        }

        // Subtract P to get [k]P: result = [k+1]P - P = [k]P
        // This is done by adding (P.x, -P.y)
        let res_x = state.res.x;
        let res_y = state.res.y;
        let p_x = input.point.x.clone();
        let p_y = input.point.y.clone();

        // Try to extract concrete values for the final subtraction witness
        let (lambda_val, x3_val, y3_val) = match (
            env.try_as_field(&res_x),
            env.try_as_field(&res_y),
            env.try_as_field(&p_x),
            env.try_as_field(&p_y),
        ) {
            (Some(res_x_f), Some(res_y_f), Some(p_x_f), Some(p_y_f)) => {
                // In witness mode: compute actual subtraction values
                let (x3_f, y3_f) = Self::subtract_point(res_x_f, res_y_f, p_x_f, p_y_f);
                // λ = (res_y + p_y) / (res_x - p_x) (subtraction formula with negated p_y)
                let lambda_f = Self::compute_lambda_add(res_x_f, res_y_f, p_x_f, -p_y_f);
                (lambda_f, x3_f, y3_f)
            }
            _ => {
                // In constraint mode: use placeholders
                (
                    C::BaseField::zero(),
                    C::BaseField::zero(),
                    C::BaseField::zero(),
                )
            }
        };

        // Allocate witnesses for the subtraction
        // λ = (res_y - (-p_y)) / (res_x - p_x) = (res_y + p_y) / (res_x - p_x)
        let lambda = {
            let pos = env.allocate();
            env.write_column(pos, env.constant(lambda_val))
        };

        // Constraint: λ * (res_x - p_x) = res_y + p_y
        let lambda_check = lambda.clone() * (res_x.clone() - p_x.clone()) - res_y.clone() - p_y;
        env.assert_zero(&lambda_check);

        // x3 = λ² - res_x - p_x
        let x3 = {
            let pos = env.allocate();
            env.write_column(pos, env.constant(x3_val))
        };
        let x3_check = x3.clone() + res_x.clone() + p_x - lambda.clone() * lambda.clone();
        env.assert_zero(&x3_check);

        // y3 = λ(res_x - x3) - res_y
        let y3 = {
            let pos = env.allocate();
            env.write_column(pos, env.constant(y3_val))
        };
        let y3_check = y3.clone() - lambda * (res_x - x3.clone()) + res_y;
        env.assert_zero(&y3_check);

        // Return [result_x, result_y, remaining_scalar (should be 0)]
        ECScalarMulInput::new(ECPoint::new(x3, y3), state.scalar)
    }

    fn output(&self, input: &Self::Input<C::BaseField>) -> Self::Output<C::BaseField> {
        let step = CurveNativeScalarMulStepGadget::<C>::new();

        // Initialize: res = P, tmp = P, scalar = k
        let mut state =
            ECScalarMulState::new(input.point.clone(), input.point.clone(), input.scalar);

        // Process each bit: after this, state contains [k+1]P
        for _ in 0..self.num_bits {
            state = step.output(&state);
        }

        // Subtract P to get [k]P: result = [k+1]P - P = [k]P
        let (result_x, result_y) =
            Self::subtract_point(state.res.x, state.res.y, input.point.x, input.point.y);

        // Return [result_x, result_y, remaining_scalar]
        ECScalarMulInput::new(ECPoint::new(result_x, result_y), state.scalar)
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
    fn test_curve_native_scalar_mul_step_gadget_constraints() {
        let gadget = CurveNativeScalarMulStepGadget::<PallasParameters>::new();

        let mut env = ConstraintEnv::<Fp>::new();

        // Create input
        let input = {
            let res_x_pos = env.allocate();
            let res_x = env.read_position(res_x_pos);
            let res_y_pos = env.allocate();
            let res_y = env.read_position(res_y_pos);
            let tmp_x_pos = env.allocate();
            let tmp_x = env.read_position(tmp_x_pos);
            let tmp_y_pos = env.allocate();
            let tmp_y = env.read_position(tmp_y_pos);
            let scalar_pos = env.allocate();
            let scalar = env.read_position(scalar_pos);
            ECScalarMulState::new(
                ECPoint::new(res_x, res_y),
                ECPoint::new(tmp_x, tmp_y),
                scalar,
            )
        };

        let _ = gadget.synthesize(&mut env, input);

        // CurveNativeScalarMulStepGadget has 10 constraints:
        // 1. bit_boolean: bit * (1 - bit) = 0 (degree 2)
        // 2. add_slope: λ * (o_x - tmp_x) - (o_y - tmp_y) = 0 (degree 2)
        // 3. sum_x: sum_x - (λ² - o_x - tmp_x) = 0 (degree 2)
        // 4. sum_y: sum_y - λ*(o_x - sum_x) + o_y = 0 (degree 2)
        // 5. double_slope: λ' * 2*tmp_y - (3*tmp_x² + a) = 0 (degree 2)
        // 6. o_x_next: o'_x - (bit*sum_x + (1-bit)*o_x) = 0 (degree 2)
        // 7. o_y_next: o'_y - (bit*sum_y + (1-bit)*o_y) = 0 (degree 2)
        // 8. tmp_x_next: tmp'_x - (λ'² - 2*tmp_x) = 0 (degree 2)
        // 9. tmp_y_next: tmp'_y - λ'*(tmp_x - tmp'_x) + tmp_y = 0 (degree 2)
        // 10. scalar_decomp: r_i - bit - 2*r' = 0 (degree 1)
        assert_eq!(
            env.num_constraints(),
            10,
            "CurveNativeScalarMulStepGadget should have 10 constraints"
        );

        // Max degree is 2
        assert_eq!(env.max_degree(), 2, "Max degree should be 2");

        env.check_degrees()
            .expect("All constraints should have degree <= MAX_DEGREE");
    }

    #[test]
    fn test_curve_native_scalar_mul_step_gadget_selector() {
        assert_eq!(
            <CurveNativeScalarMulStepGadget<PallasParameters> as TypedGadget<Fp>>::Selector::GADGET,
            crate::column::Gadget::EllipticCurveScaling
        );
        assert_eq!(
            <CurveNativeScalarMulStepGadget<PallasParameters> as TypedGadget<Fp>>::Selector::INDEX,
            9
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
    use ark_ff::Zero;
    use mina_curves::pasta::{Fp, Pallas, PallasParameters};
    use rand::{Rng, SeedableRng};

    #[test]
    fn test_curve_native_scalar_mul_step_gadget_bit_decomposition() {
        let gadget = CurveNativeScalarMulStepGadget::<PallasParameters>::new();

        let g = Pallas::generator();

        // Test with scalar = 5 = 101 in binary
        let scalar = Fp::from(5u64);
        let input = ECScalarMulState::new(ECPoint::new(g.x, g.y), ECPoint::new(g.x, g.y), scalar);

        let output = gadget.output(&input);

        // After one step:
        // - bit = 1 (LSB of 5)
        // - next_scalar = 2 (5 >> 1)
        assert_eq!(output.scalar, Fp::from(2u64), "Scalar should be halved");
    }

    #[test]
    fn test_curve_native_scalar_mul_step_gadget_random() {
        let seed: u64 = rand::random();
        println!("test_curve_native_scalar_mul_step_gadget_random seed: {seed}");
        let mut rng = rand::rngs::StdRng::seed_from_u64(seed);

        let gadget = CurveNativeScalarMulStepGadget::<PallasParameters>::new();

        let scalar: u64 = rng.gen_range(1..1_000_000);
        let s: u64 = rng.gen_range(1..1_000_000);

        let p: Pallas = Pallas::generator().mul_bigint([s]).into();

        let input = ECScalarMulState::new(
            ECPoint::new(p.x, p.y),
            ECPoint::new(p.x, p.y),
            Fp::from(scalar),
        );
        let output = gadget.output(&input);

        // Scalar should be halved
        let expected_next_scalar = scalar >> 1;
        assert_eq!(
            output.scalar,
            Fp::from(expected_next_scalar),
            "Scalar should be halved"
        );
    }

    #[test]
    fn test_curve_native_scalar_mul_gadget_small() {
        let gadget = CurveNativeScalarMulGadget::<PallasParameters>::new(4);

        let g = Pallas::generator();
        let scalar = Fp::from(3u64);
        let input = ECScalarMulInput::new(ECPoint::new(g.x, g.y), scalar);
        let output = gadget.output(&input);

        // The remaining scalar should be 0 after 4 bits (3 < 16)
        assert_eq!(output.scalar, Fp::zero(), "Scalar should be fully consumed");
    }

    #[test]
    fn test_curve_native_scalar_mul_gadget_deterministic() {
        let gadget = CurveNativeScalarMulGadget::<PallasParameters>::new(8);

        let g = Pallas::generator();
        let scalar = Fp::from(42u64);
        let input = ECScalarMulInput::new(ECPoint::new(g.x, g.y), scalar);

        let output1 = gadget.output(&input);
        let output2 = gadget.output(&input);

        assert_eq!(output1, output2, "Same inputs should give same outputs");
    }

    #[test]
    fn test_curve_native_scalar_mul_gadget_various_scalars() {
        let gadget = CurveNativeScalarMulGadget::<PallasParameters>::new(16);

        let g = Pallas::generator();

        // Test various small scalars
        let scalars: Vec<u64> = vec![1, 2, 3, 4, 5, 7, 10, 15, 16, 100, 255];

        for scalar in scalars {
            let input = ECScalarMulInput::new(ECPoint::new(g.x, g.y), Fp::from(scalar));
            let output = gadget.output(&input);

            // Scalar should be fully consumed after 16 bits
            assert_eq!(
                output.scalar,
                Fp::zero(),
                "Scalar {} should be fully consumed",
                scalar
            );
        }
    }

    #[test]
    fn test_curve_native_scalar_mul_gadget_random_scalar() {
        let seed: u64 = rand::random();
        println!("test_curve_native_scalar_mul_gadget_random_scalar seed: {seed}");
        let mut rng = rand::rngs::StdRng::seed_from_u64(seed);

        let gadget = CurveNativeScalarMulGadget::<PallasParameters>::new(32);

        let scalar: u32 = rng.gen();
        let s: u64 = rng.gen_range(1..1_000);
        let p: Pallas = Pallas::generator().mul_bigint([s]).into();

        let input = ECScalarMulInput::new(ECPoint::new(p.x, p.y), Fp::from(scalar));
        let output = gadget.output(&input);

        // Scalar should be fully consumed after 32 bits
        assert_eq!(
            output.scalar,
            Fp::zero(),
            "Scalar {} should be fully consumed",
            scalar
        );
    }

    /// Verify that output positions correctly describe where outputs are written in the trace.
    #[test]
    fn test_curve_native_scalar_mul_step_gadget_output_positions_match_trace() {
        use crate::{
            circuit::{CircuitEnv, Trace},
            circuits::gadget::test_utils::verify_trace_positions,
        };

        let gadget = CurveNativeScalarMulStepGadget::<PallasParameters>::new();
        let mut env = Trace::<Fp>::new(16);

        // Use the generator as input point
        let g = Pallas::generator();
        let (o_x, o_y) = (g.x, g.y);
        let (tmp_x, tmp_y) = (g.x, g.y);
        let scalar = Fp::from(5u64); // 101 in binary

        // Allocate and write inputs
        let o_x_pos = env.allocate();
        let o_x_var = env.write_column(o_x_pos, o_x);
        let o_y_pos = env.allocate();
        let o_y_var = env.write_column(o_y_pos, o_y);
        let tmp_x_pos = env.allocate();
        let tmp_x_var = env.write_column(tmp_x_pos, tmp_x);
        let tmp_y_pos = env.allocate();
        let tmp_y_var = env.write_column(tmp_y_pos, tmp_y);
        let scalar_pos = env.allocate();
        let scalar_var = env.write_column(scalar_pos, scalar);

        let input = ECScalarMulState::new(
            ECPoint::new(o_x_var, o_y_var),
            ECPoint::new(tmp_x_var, tmp_y_var),
            scalar_var,
        );

        let current_row = env.current_row();

        // Synthesize
        let _output = gadget.synthesize(&mut env, input);

        // Compute expected output
        let expected_output = gadget.output(&ECScalarMulState::new(
            ECPoint::new(o_x, o_y),
            ECPoint::new(tmp_x, tmp_y),
            scalar,
        ));

        // Verify input positions
        verify_trace_positions(
            &env,
            current_row,
            <CurveNativeScalarMulStepGadget<PallasParameters> as TypedGadget<Fp>>::input_positions(
            ),
            &[o_x, o_y, tmp_x, tmp_y, scalar],
            "input",
        );

        // Verify output positions (on next row)
        verify_trace_positions(
            &env,
            current_row,
            <CurveNativeScalarMulStepGadget<PallasParameters> as TypedGadget<Fp>>::output_positions(
            ),
            &[
                expected_output.res.x,
                expected_output.res.y,
                expected_output.tmp.x,
                expected_output.tmp.y,
                expected_output.scalar,
            ],
            "output",
        );
    }

    /// Verify that CurveNativeScalarMulGadget produces correct output in trace.
    /// Note: This gadget spans multiple rows, so we verify the final output matches
    /// the expected computation.
    #[test]
    fn test_curve_native_scalar_mul_gadget_output_positions_match_trace() {
        use crate::{
            circuit::{CircuitEnv, Trace},
            circuits::gadget::test_utils::verify_trace_positions,
        };

        let num_bits = 4;
        let gadget = CurveNativeScalarMulGadget::<PallasParameters>::new(num_bits);
        // Need enough rows: num_bits + 2 (for step rows and final row)
        let mut env = Trace::<Fp>::new(num_bits + 4);

        // Use the generator and a small scalar
        let g = Pallas::generator();
        let (p_x, p_y) = (g.x, g.y);
        let scalar = Fp::from(3u64); // Small scalar for 4 bits

        // Allocate and write inputs
        let p_x_pos = env.allocate();
        let p_x_var = env.write_column(p_x_pos, p_x);
        let p_y_pos = env.allocate();
        let p_y_var = env.write_column(p_y_pos, p_y);
        let scalar_pos = env.allocate();
        let scalar_var = env.write_column(scalar_pos, scalar);

        let input = ECScalarMulInput::new(ECPoint::new(p_x_var, p_y_var), scalar_var);

        let start_row = env.current_row();

        // Synthesize
        let _output = gadget.synthesize(&mut env, input);

        // After synthesis, the output is on the current row (after all steps + final subtraction)
        let final_row = env.current_row();

        // Compute expected output
        let expected_output = gadget.output(&ECScalarMulInput::new(ECPoint::new(p_x, p_y), scalar));

        // Verify input positions (on start row)
        verify_trace_positions(
            &env,
            start_row,
            <CurveNativeScalarMulGadget<PallasParameters> as TypedGadget<Fp>>::input_positions(),
            &[p_x, p_y, scalar],
            "input",
        );

        // Verify output positions (on final row)
        // Output positions are: col 5 (x3), col 6 (y3), col 4 (remaining scalar)
        verify_trace_positions(
            &env,
            final_row,
            <CurveNativeScalarMulGadget<PallasParameters> as TypedGadget<Fp>>::output_positions(),
            &[
                expected_output.point.x,
                expected_output.point.y,
                expected_output.scalar,
            ],
            "output",
        );
    }
}
