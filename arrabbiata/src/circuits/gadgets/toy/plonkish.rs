//! Standard Plonkish gadget with 3 wires.
//!
//! Implements the standard Plonkish constraint relation:
//!
//! ```text
//! q_L * a + q_R * b + q_O * c + q_M * a * b + q_C = 0
//! ```
//!
//! Where:
//! - `a`, `b`, `c` are the three wires (left, right, output)
//! - `q_L`, `q_R`, `q_O`, `q_M`, `q_C` are the gate selectors
//!
//! ## Examples
//!
//! Addition gate: `a + b = c`
//! ```
//! use arrabbiata::circuits::gadgets::PlonkishGadget;
//! use mina_curves::pasta::Fp;
//!
//! let add_gate = PlonkishGadget::<Fp>::addition();
//! ```
//!
//! Multiplication gate: `a * b = c`
//! ```
//! use arrabbiata::circuits::gadgets::PlonkishGadget;
//! use mina_curves::pasta::Fp;
//!
//! let mul_gate = PlonkishGadget::<Fp>::multiplication();
//! ```
//!
//! Custom gate: `2*a + 3*b - c + a*b + 5 = 0`
//! ```
//! use arrabbiata::circuits::gadgets::PlonkishGadget;
//! use mina_curves::pasta::Fp;
//!
//! let custom = PlonkishGadget::<Fp>::new(
//!     Fp::from(2u64),  // q_L
//!     Fp::from(3u64),  // q_R
//!     -Fp::from(1u64), // q_O
//!     Fp::from(1u64),  // q_M
//!     Fp::from(5u64),  // q_C
//! );
//! ```

use ark_ff::PrimeField;

use crate::{
    circuit::{CircuitEnv, SelectorEnv},
    circuits::{
        gadget::{Position, Row, TypedGadget},
        selector::QApp,
        types::{Arity, Triple},
    },
};

// ============================================================================
// PlonkishGadget
// ============================================================================

/// A standard Plonkish gate with 3 wires and configurable selectors.
///
/// Enforces the constraint: `q_L * a + q_R * b + q_O * c + q_M * a * b + q_C = 0`
///
/// Common configurations:
/// - Addition: `q_L=1, q_R=1, q_O=-1, q_M=0, q_C=0` → `a + b = c`
/// - Multiplication: `q_L=0, q_R=0, q_O=-1, q_M=1, q_C=0` → `a * b = c`
/// - Constant: `q_L=0, q_R=0, q_O=1, q_M=0, q_C=-k` → `c = k`
/// - Bool check: `q_L=0, q_R=0, q_O=-1, q_M=1, q_C=0` with `a=b=c` → `c*(c-1)=0`
#[derive(Clone, Debug)]
pub struct PlonkishGadget<F: PrimeField> {
    /// Selector for wire `a` (left input)
    pub q_l: F,
    /// Selector for wire `b` (right input)
    pub q_r: F,
    /// Selector for wire `c` (output)
    pub q_o: F,
    /// Selector for multiplication term `a * b`
    pub q_m: F,
    /// Constant term
    pub q_c: F,
}

impl<F: PrimeField> PlonkishGadget<F> {
    /// Create a new Plonkish gate with the given selectors.
    pub fn new(q_l: F, q_r: F, q_o: F, q_m: F, q_c: F) -> Self {
        Self {
            q_l,
            q_r,
            q_o,
            q_m,
            q_c,
        }
    }

    /// Create an addition gate: `a + b = c`
    pub fn addition() -> Self {
        Self::new(F::one(), F::one(), -F::one(), F::zero(), F::zero())
    }

    /// Create a multiplication gate: `a * b = c`
    pub fn multiplication() -> Self {
        Self::new(F::zero(), F::zero(), -F::one(), F::one(), F::zero())
    }

    /// Create a constant gate: `c = k`
    pub fn constant(k: F) -> Self {
        Self::new(F::zero(), F::zero(), F::one(), F::zero(), -k)
    }

    /// Create a left wire pass-through: `a = c`
    pub fn left_passthrough() -> Self {
        Self::new(F::one(), F::zero(), -F::one(), F::zero(), F::zero())
    }

    /// Create a right wire pass-through: `b = c`
    pub fn right_passthrough() -> Self {
        Self::new(F::zero(), F::one(), -F::one(), F::zero(), F::zero())
    }

    /// Create a linear combination gate: `k1*a + k2*b = c`
    pub fn linear_combination(k1: F, k2: F) -> Self {
        Self::new(k1, k2, -F::one(), F::zero(), F::zero())
    }

    /// Create a multiply-add gate: `a * b + k = c`
    pub fn multiply_add(k: F) -> Self {
        Self::new(F::zero(), F::zero(), -F::one(), F::one(), k)
    }

    /// Compute the output `c` given inputs `a` and `b`.
    ///
    /// From `q_L * a + q_R * b + q_O * c + q_M * a * b + q_C = 0`, we get:
    /// `c = -(q_L * a + q_R * b + q_M * a * b + q_C) / q_O`
    ///
    /// Panics if `q_O` is zero (cannot compute output).
    pub fn compute_output(&self, a: F, b: F) -> F {
        assert!(!self.q_o.is_zero(), "q_O cannot be zero to compute output");
        let numerator = self.q_l * a + self.q_r * b + self.q_m * a * b + self.q_c;
        -numerator / self.q_o
    }

    /// Check if the constraint is satisfied for given wire values.
    pub fn is_satisfied(&self, a: F, b: F, c: F) -> bool {
        let result = self.q_l * a + self.q_r * b + self.q_o * c + self.q_m * a * b + self.q_c;
        result.is_zero()
    }
}

// Position constants for PlonkishGadget
const PLONKISH_INPUT_POSITIONS: &[Position] = &[
    Position {
        col: 0,
        row: Row::Curr,
    }, // a
    Position {
        col: 1,
        row: Row::Curr,
    }, // b
    Position {
        col: 2,
        row: Row::Curr,
    }, // c (input for pass-through)
];

const PLONKISH_OUTPUT_POSITIONS: &[Position] = &[Position {
    col: 2,
    row: Row::Curr,
}]; // c

impl<F: PrimeField> TypedGadget<F> for PlonkishGadget<F> {
    type Selector = QApp;
    type Input<V: Clone> = Triple<V>;
    type Output<V: Clone> = Triple<V>;
    const ROWS: usize = 1;

    fn input_positions() -> &'static [Position] {
        PLONKISH_INPUT_POSITIONS
    }

    fn output_positions() -> &'static [Position] {
        PLONKISH_OUTPUT_POSITIONS
    }

    fn synthesize<E: CircuitEnv<F> + SelectorEnv<F>>(
        &self,
        env: &mut E,
        input: Self::Input<E::Variable>,
    ) -> Self::Output<E::Variable> {
        let a = input.first.clone();
        let b = input.second.clone();
        let c = input.third.clone();

        // Build the constraint: q_L * a + q_R * b + q_O * c + q_M * a * b + q_C = 0
        let q_l = env.constant(self.q_l);
        let q_r = env.constant(self.q_r);
        let q_o = env.constant(self.q_o);
        let q_m = env.constant(self.q_m);
        let q_c = env.constant(self.q_c);

        let term_l = q_l * a.clone();
        let term_r = q_r * b.clone();
        let term_o = q_o * c.clone();
        let term_m = q_m * (a.clone() * b.clone());
        let constraint = term_l + term_r + term_o + term_m + q_c;

        env.assert_zero_named("plonkish", &constraint);

        // Return the input unchanged (gate just enforces constraint)
        input
    }

    fn output(&self, input: &Self::Input<F>) -> Self::Output<F> {
        // Pass through - the constraint is enforced, values unchanged
        input.clone()
    }
}

// Compile-time verification that position counts match arities
const _: () = crate::circuits::types::check_arity::<
    { PLONKISH_INPUT_POSITIONS.len() },
    { Triple::<()>::SIZE },
>();

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuit::{ConstraintEnv, Trace};
    use mina_curves::pasta::Fp;

    #[test]
    fn test_plonkish_addition_gate() {
        let gate = PlonkishGadget::<Fp>::addition();

        // 3 + 5 = 8
        let a = Fp::from(3u64);
        let b = Fp::from(5u64);
        let c = gate.compute_output(a, b);
        assert_eq!(c, Fp::from(8u64));

        assert!(gate.is_satisfied(a, b, c));
        assert!(!gate.is_satisfied(a, b, Fp::from(7u64)));
    }

    #[test]
    fn test_plonkish_multiplication_gate() {
        let gate = PlonkishGadget::<Fp>::multiplication();

        // 3 * 5 = 15
        let a = Fp::from(3u64);
        let b = Fp::from(5u64);
        let c = gate.compute_output(a, b);
        assert_eq!(c, Fp::from(15u64));

        assert!(gate.is_satisfied(a, b, c));
        assert!(!gate.is_satisfied(a, b, Fp::from(14u64)));
    }

    #[test]
    fn test_plonkish_constant_gate() {
        let gate = PlonkishGadget::<Fp>::constant(Fp::from(42u64));

        // c = 42 (a and b don't matter)
        let c = gate.compute_output(Fp::from(0u64), Fp::from(0u64));
        assert_eq!(c, Fp::from(42u64));

        assert!(gate.is_satisfied(Fp::from(123u64), Fp::from(456u64), Fp::from(42u64)));
    }

    #[test]
    fn test_plonkish_linear_combination() {
        let gate = PlonkishGadget::<Fp>::linear_combination(Fp::from(2u64), Fp::from(3u64));

        // 2*4 + 3*5 = 23
        let a = Fp::from(4u64);
        let b = Fp::from(5u64);
        let c = gate.compute_output(a, b);
        assert_eq!(c, Fp::from(23u64));

        assert!(gate.is_satisfied(a, b, c));
    }

    #[test]
    fn test_plonkish_multiply_add() {
        let gate = PlonkishGadget::<Fp>::multiply_add(Fp::from(10u64));

        // 3 * 4 + 10 = 22
        let a = Fp::from(3u64);
        let b = Fp::from(4u64);
        let c = gate.compute_output(a, b);
        assert_eq!(c, Fp::from(22u64));

        assert!(gate.is_satisfied(a, b, c));
    }

    #[test]
    fn test_plonkish_passthrough_left() {
        let gate = PlonkishGadget::<Fp>::left_passthrough();

        // c = a (b doesn't matter)
        let a = Fp::from(42u64);
        let b = Fp::from(999u64);
        let c = gate.compute_output(a, b);
        assert_eq!(c, a);

        assert!(gate.is_satisfied(a, b, a));
    }

    #[test]
    fn test_plonkish_passthrough_right() {
        let gate = PlonkishGadget::<Fp>::right_passthrough();

        // c = b (a doesn't matter)
        let a = Fp::from(999u64);
        let b = Fp::from(42u64);
        let c = gate.compute_output(a, b);
        assert_eq!(c, b);

        assert!(gate.is_satisfied(a, b, b));
    }

    #[test]
    fn test_plonkish_constraints() {
        let gate = PlonkishGadget::<Fp>::addition();

        let mut env = ConstraintEnv::<Fp>::new();

        // Allocate wires
        let a_pos = env.allocate();
        let b_pos = env.allocate();
        let c_pos = env.allocate();

        let a = env.read_position(a_pos);
        let b = env.read_position(b_pos);
        let c = env.read_position(c_pos);

        let input = Triple::new(a, b, c);
        let _ = gate.synthesize(&mut env, input);

        // Should have exactly 1 constraint
        assert_eq!(
            env.num_constraints(),
            1,
            "PlonkishGadget should have 1 constraint"
        );
        assert_eq!(
            env.num_named_constraints(),
            1,
            "PlonkishGadget should have 1 named constraint"
        );

        // Max degree depends on gate type. Addition is degree 1, multiplication is degree 2.
        assert_eq!(env.max_degree(), 1, "Addition gate should have degree 1");

        env.check_degrees()
            .expect("All constraints should have degree <= MAX_DEGREE");
    }

    #[test]
    fn test_plonkish_multiplication_constraints() {
        let gate = PlonkishGadget::<Fp>::multiplication();

        let mut env = ConstraintEnv::<Fp>::new();

        let a_pos = env.allocate();
        let b_pos = env.allocate();
        let c_pos = env.allocate();

        let a = env.read_position(a_pos);
        let b = env.read_position(b_pos);
        let c = env.read_position(c_pos);

        let input = Triple::new(a, b, c);
        let _ = gate.synthesize(&mut env, input);

        // Multiplication gate has degree 2 (from a * b term)
        assert_eq!(
            env.max_degree(),
            2,
            "Multiplication gate should have degree 2"
        );
    }

    #[test]
    fn test_plonkish_trace() {
        let gate = PlonkishGadget::<Fp>::addition();
        let mut env = Trace::<Fp>::new(16);

        // 3 + 5 = 8
        let a_val = Fp::from(3u64);
        let b_val = Fp::from(5u64);
        let c_val = gate.compute_output(a_val, b_val);

        let a_pos = env.allocate();
        let a = env.write_column(a_pos, a_val);

        let b_pos = env.allocate();
        let b = env.write_column(b_pos, b_val);

        let c_pos = env.allocate();
        let c = env.write_column(c_pos, c_val);

        let input = Triple::new(a, b, c);
        let output = gate.synthesize(&mut env, input);

        // Output should be the same as input (pass-through)
        assert_eq!(output.first, a_val);
        assert_eq!(output.second, b_val);
        assert_eq!(output.third, c_val);

        // Verify trace
        assert_eq!(env.get(0, 0), Some(&a_val));
        assert_eq!(env.get(0, 1), Some(&b_val));
        assert_eq!(env.get(0, 2), Some(&c_val));
    }

    #[test]
    fn test_plonkish_custom_gate() {
        // Custom gate: 2*a - 3*b + a*b + 7 = c
        // Rewritten: 2*a - 3*b - c + a*b + 7 = 0
        let gate = PlonkishGadget::<Fp>::new(
            Fp::from(2u64),  // q_L
            -Fp::from(3u64), // q_R
            -Fp::from(1u64), // q_O
            Fp::from(1u64),  // q_M
            Fp::from(7u64),  // q_C
        );

        // a=4, b=2: 2*4 - 3*2 + 4*2 + 7 = 8 - 6 + 8 + 7 = 17
        let a = Fp::from(4u64);
        let b = Fp::from(2u64);
        let c = gate.compute_output(a, b);
        assert_eq!(c, Fp::from(17u64));

        assert!(gate.is_satisfied(a, b, c));
    }

    /// Regression test for gadget metrics.
    #[test]
    fn test_plonkish_gadget_metrics() {
        let gate = PlonkishGadget::<Fp>::multiplication();

        let mut env = ConstraintEnv::<Fp>::new();

        let a_pos = env.allocate();
        let b_pos = env.allocate();
        let c_pos = env.allocate();

        let a = env.read_position(a_pos);
        let b = env.read_position(b_pos);
        let c = env.read_position(c_pos);

        let input = Triple::new(a, b, c);
        let _ = gate.synthesize(&mut env, input);

        assert_eq!(env.num_constraints(), 1, "constraints changed");
        assert_eq!(
            env.num_witness_allocations(),
            3,
            "witness allocations changed"
        );
        assert_eq!(env.max_degree(), 2, "max degree changed");
    }
}
