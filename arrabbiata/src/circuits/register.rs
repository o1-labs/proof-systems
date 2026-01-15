//! Typed Registers for Permutation Arguments
//!
//! This module provides a type-safe interface for "registers" - named storage
//! locations that can be written and read across circuit rows. The consistency
//! between writes and reads is enforced via PlonK's permutation argument.
//!
//! ## PlonK Permutation Argument
//!
//! In PlonK, the permutation argument (also called "copy constraints") ensures
//! that certain wire values are equal across different positions in the circuit.
//! This is achieved by:
//!
//! 1. Defining a permutation σ that maps positions to positions
//! 2. Proving that w(i) = w(σ(i)) for all positions i
//!
//! The permutation polynomial identity is:
//!
//! ```text
//! ∏ᵢ (wᵢ + β·σ(i) + γ) = ∏ᵢ (wᵢ + β·i + γ)
//! ```
//!
//! Where:
//! - wᵢ is the wire value at position i
//! - σ(i) is the permutation (maps i to the position it should equal)
//! - β, γ are random challenges
//!
//! ## Register Model
//!
//! Registers provide a high-level abstraction over copy constraints:
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                     Circuit Execution                        │
//! ├─────────────────────────────────────────────────────────────┤
//! │  Row 0:  reg_store::<Digest>(x)     → stores x at position A │
//! │  Row 1:  ...                                                 │
//! │  Row 2:  ...                                                 │
//! │  Row N:  y = reg_load::<Digest>()   → loads from position A  │
//! │                                                              │
//! │  Permutation: σ(position_of_y) = position_of_x              │
//! │  Constraint:  y = x  (enforced by permutation argument)      │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Usage
//!
//! ```ignore
//! use arrabbiata::circuits::register::{Register, RegisterEnv};
//!
//! // Define a register type
//! #[derive(Clone, Copy, Debug, Default)]
//! struct Digest;
//!
//! impl Register for Digest {
//!     const INDEX: usize = 0;
//!     const NAME: &'static str = "digest";
//! }
//!
//! // In circuit synthesis:
//! fn synthesize<E: CircuitEnv<F> + RegisterEnv<F>>(env: &mut E) {
//!     let value = env.constant(F::from(42u64));
//!
//!     // Store value in register
//!     env.reg_store::<Digest>(value.clone());
//!
//!     // ... many rows later ...
//!
//!     // Load value from register (creates copy constraint)
//!     let loaded = env.reg_load::<Digest>();
//!
//!     // loaded is now constrained to equal value via permutation
//! }
//! ```
//!
//! ## Registers vs External Memory
//!
//! There are two mechanisms for "memory" in the circuit:
//!
//! 1. **Registers (this module)**: For values within the execution trace.
//!    Uses PlonK's permutation argument to enforce equality between cells.
//!    - Fast: O(1) per access
//!    - Limited: Values must be in the trace
//!    - Use case: Passing state between rows, IVC accumulators
//!
//! 2. **External Memory (via lookups)**: For values outside the trace.
//!    Uses lookup protocols (e.g., Plookup, LogUp) to prove membership.
//!    - Flexible: Can access large tables
//!    - Overhead: Requires auxiliary columns for lookup arguments
//!    - Use case: ROM tables, range checks, precomputed values
//!
//! ## Future Extensions
//!
//! This module will be extended to support:
//! - Multi-value registers (storing tuples)
//! - Register banks (groups of related registers)
//! - Versioned registers (for RAM-like semantics within trace)

use ark_ff::PrimeField;
use core::fmt::Debug;

use crate::circuit::CircuitEnv;

// ============================================================================
// Register Trait
// ============================================================================

/// Marker trait for typed registers.
///
/// Each register type represents a named storage location in the circuit.
/// The `INDEX` provides a unique identifier for the permutation argument,
/// and `NAME` is used for debugging and error messages.
///
/// # Implementing a Register
///
/// ```
/// use arrabbiata::circuits::register::Register;
///
/// #[derive(Clone, Copy, Debug, Default)]
/// struct MyRegister;
///
/// impl Register for MyRegister {
///     const INDEX: usize = 0;
///     const NAME: &'static str = "my_register";
/// }
/// ```
///
/// # Index Assignment
///
/// Register indices should be assigned sequentially starting from 0.
/// Each register type must have a unique index to ensure the permutation
/// argument correctly identifies which values should be equal.
pub trait Register: 'static + Copy + Clone + Debug + Default + Send + Sync {
    /// Unique index for this register in the permutation argument.
    ///
    /// This index is used to:
    /// 1. Identify the register in the permutation polynomial
    /// 2. Map store/load operations to specific wire positions
    const INDEX: usize;

    /// Human-readable name for debugging and error messages.
    const NAME: &'static str;
}

// ============================================================================
// Register State
// ============================================================================

/// Tracks which registers have been stored.
///
/// This ensures the invariant that a register must be stored before it can
/// be loaded. Attempting to load from an empty register will panic.
#[derive(Clone, Debug)]
pub struct RegisterState<const N: usize> {
    /// Bitmap of which registers have been stored.
    /// `stored[i]` is true if register with INDEX=i has been stored.
    stored: [bool; N],
}

impl<const N: usize> Default for RegisterState<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> RegisterState<N> {
    /// Create a new register state with all registers empty.
    pub fn new() -> Self {
        Self { stored: [false; N] }
    }

    /// Mark a register as stored.
    ///
    /// # Panics
    ///
    /// Panics if the register index is out of bounds.
    pub fn store<R: Register>(&mut self) {
        assert!(
            R::INDEX < N,
            "Register index {} out of bounds (max {})",
            R::INDEX,
            N
        );
        self.stored[R::INDEX] = true;
    }

    /// Check if a register has been stored, panic if not.
    ///
    /// # Panics
    ///
    /// Panics if the register has not been stored (is empty).
    pub fn check_stored<R: Register>(&self) {
        assert!(
            R::INDEX < N,
            "Register index {} out of bounds (max {})",
            R::INDEX,
            N
        );
        assert!(
            self.stored[R::INDEX],
            "Cannot load from empty register '{}' (index {}): must store before load",
            R::NAME,
            R::INDEX
        );
    }

    /// Check if a register has been stored (non-panicking).
    pub fn is_stored<R: Register>(&self) -> bool {
        R::INDEX < N && self.stored[R::INDEX]
    }

    /// Reset all registers to empty state.
    pub fn reset(&mut self) {
        self.stored = [false; N];
    }
}

// ============================================================================
// RegisterEnv Trait
// ============================================================================

/// Environment trait for register operations.
///
/// This trait extends `CircuitEnv` with register store/load operations.
/// Implementations must track which registers have been stored and panic
/// if a load is attempted on an empty register.
///
/// # Store-Before-Load Invariant
///
/// A register **must** be stored before it can be loaded. This is enforced
/// at runtime:
///
/// ```ignore
/// // OK: store then load
/// env.reg_store::<DigestReg>(value);
/// let v = env.reg_load::<DigestReg>();  // works
///
/// // ERROR: load before store
/// let v = env.reg_load::<DigestReg>();  // panics!
/// ```
///
/// # Multiple Stores
///
/// A register can be stored multiple times. Each store overwrites the
/// previous value. The load always returns the most recently stored value.
pub trait RegisterEnv<F: PrimeField>: CircuitEnv<F> {
    /// Store a value in a typed register.
    ///
    /// This records the (position, value) pair for the permutation argument.
    /// The position is determined by the current row and register index.
    ///
    /// Multiple stores to the same register are allowed; each store
    /// overwrites the previous value.
    fn reg_store<R: Register>(&mut self, value: Self::Variable);

    /// Load a value from a typed register.
    ///
    /// This creates a new variable and records a copy constraint via the
    /// permutation argument. The returned variable is constrained to equal
    /// the most recently stored value in this register.
    ///
    /// # Panics
    ///
    /// Panics if the register has not been stored (is empty).
    fn reg_load<R: Register>(&mut self) -> Self::Variable;

    /// Create an explicit copy constraint between two variables.
    ///
    /// This adds the pair to the permutation argument, ensuring a = b.
    fn copy(&mut self, a: &Self::Variable, b: &Self::Variable);
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // Test registers (defined locally for testing)
    #[derive(Clone, Copy, Debug, Default)]
    struct TestReg0;
    impl Register for TestReg0 {
        const INDEX: usize = 0;
        const NAME: &'static str = "test_reg_0";
    }

    #[derive(Clone, Copy, Debug, Default)]
    struct TestReg1;
    impl Register for TestReg1 {
        const INDEX: usize = 1;
        const NAME: &'static str = "test_reg_1";
    }

    #[derive(Clone, Copy, Debug, Default)]
    struct TestReg2;
    impl Register for TestReg2 {
        const INDEX: usize = 2;
        const NAME: &'static str = "test_reg_2";
    }

    const NUM_TEST_REGISTERS: usize = 3;

    // ========================================================================
    // Register Trait Tests
    // ========================================================================

    #[test]
    fn test_register_indices_unique() {
        assert_ne!(TestReg0::INDEX, TestReg1::INDEX);
        assert_ne!(TestReg0::INDEX, TestReg2::INDEX);
        assert_ne!(TestReg1::INDEX, TestReg2::INDEX);
    }

    #[test]
    fn test_register_indices_sequential() {
        assert_eq!(TestReg0::INDEX, 0);
        assert_eq!(TestReg1::INDEX, 1);
        assert_eq!(TestReg2::INDEX, 2);
    }

    #[test]
    fn test_register_names() {
        assert_eq!(TestReg0::NAME, "test_reg_0");
        assert_eq!(TestReg1::NAME, "test_reg_1");
        assert_eq!(TestReg2::NAME, "test_reg_2");
    }

    // ========================================================================
    // RegisterState Tests
    // ========================================================================

    #[test]
    fn test_register_state_new() {
        let state = RegisterState::<NUM_TEST_REGISTERS>::new();
        assert!(!state.is_stored::<TestReg0>());
        assert!(!state.is_stored::<TestReg1>());
        assert!(!state.is_stored::<TestReg2>());
    }

    #[test]
    fn test_register_state_store() {
        let mut state = RegisterState::<NUM_TEST_REGISTERS>::new();

        // Initially empty
        assert!(!state.is_stored::<TestReg0>());

        // Store marks as stored
        state.store::<TestReg0>();
        assert!(state.is_stored::<TestReg0>());

        // Other registers remain empty
        assert!(!state.is_stored::<TestReg1>());
        assert!(!state.is_stored::<TestReg2>());
    }

    #[test]
    fn test_register_state_check_stored_after_store() {
        let mut state = RegisterState::<NUM_TEST_REGISTERS>::new();
        state.store::<TestReg0>();

        // Should not panic
        state.check_stored::<TestReg0>();
    }

    #[test]
    #[should_panic(expected = "Cannot load from empty register 'test_reg_0'")]
    fn test_register_state_check_stored_before_store_panics() {
        let state = RegisterState::<NUM_TEST_REGISTERS>::new();

        // Should panic: register is empty
        state.check_stored::<TestReg0>();
    }

    #[test]
    #[should_panic(expected = "Cannot load from empty register 'test_reg_1'")]
    fn test_register_state_load_wrong_register_panics() {
        let mut state = RegisterState::<NUM_TEST_REGISTERS>::new();

        // Store reg0, but try to load reg1
        state.store::<TestReg0>();
        state.check_stored::<TestReg1>(); // Should panic
    }

    #[test]
    fn test_register_state_multiple_stores() {
        let mut state = RegisterState::<NUM_TEST_REGISTERS>::new();

        // Multiple stores to same register are allowed
        state.store::<TestReg0>();
        state.store::<TestReg0>();
        state.store::<TestReg0>();

        assert!(state.is_stored::<TestReg0>());
        state.check_stored::<TestReg0>(); // Should not panic
    }

    #[test]
    fn test_register_state_reset() {
        let mut state = RegisterState::<NUM_TEST_REGISTERS>::new();

        // Store all registers
        state.store::<TestReg0>();
        state.store::<TestReg1>();
        state.store::<TestReg2>();

        assert!(state.is_stored::<TestReg0>());
        assert!(state.is_stored::<TestReg1>());
        assert!(state.is_stored::<TestReg2>());

        // Reset clears all
        state.reset();

        assert!(!state.is_stored::<TestReg0>());
        assert!(!state.is_stored::<TestReg1>());
        assert!(!state.is_stored::<TestReg2>());
    }

    #[test]
    fn test_register_state_default() {
        let state = RegisterState::<NUM_TEST_REGISTERS>::default();
        assert!(!state.is_stored::<TestReg0>());
        assert!(!state.is_stored::<TestReg1>());
        assert!(!state.is_stored::<TestReg2>());
    }

    #[test]
    #[should_panic(expected = "Register index 5 out of bounds")]
    fn test_register_state_out_of_bounds_store() {
        let mut state = RegisterState::<3>::new();

        #[derive(Clone, Copy, Debug, Default)]
        struct BadReg;
        impl Register for BadReg {
            const INDEX: usize = 5;
            const NAME: &'static str = "bad";
        }

        state.store::<BadReg>(); // Should panic
    }

    #[test]
    fn test_register_state_is_stored_out_of_bounds_returns_false() {
        let state = RegisterState::<3>::new();

        #[derive(Clone, Copy, Debug, Default)]
        struct BadReg;
        impl Register for BadReg {
            const INDEX: usize = 5;
            const NAME: &'static str = "bad";
        }

        // is_stored returns false for out-of-bounds (non-panicking)
        assert!(!state.is_stored::<BadReg>());
    }
}
