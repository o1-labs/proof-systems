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

use core::fmt::Debug;

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
// Standard Registers
// ============================================================================

/// Register for the sponge digest (used in IVC).
#[derive(Clone, Copy, Debug, Default)]
pub struct DigestReg;

impl Register for DigestReg {
    const INDEX: usize = 0;
    const NAME: &'static str = "digest";
}

/// Register for the accumulated homogenizer u.
#[derive(Clone, Copy, Debug, Default)]
pub struct UAccReg;

impl Register for UAccReg {
    const INDEX: usize = 1;
    const NAME: &'static str = "u_acc";
}

/// Register for the accumulated constraint combiner α.
#[derive(Clone, Copy, Debug, Default)]
pub struct AlphaAccReg;

impl Register for AlphaAccReg {
    const INDEX: usize = 2;
    const NAME: &'static str = "alpha_acc";
}

// ============================================================================
// RegisterEnv Trait
// ============================================================================

// Note: The RegisterEnv trait will be added to circuit.rs once we implement
// the permutation argument infrastructure. For now, we define the registers
// and their indices.
//
// The trait will look like:
//
// ```
// pub trait RegisterEnv<F: PrimeField>: CircuitEnv<F> {
//     /// Store a value in a typed register.
//     ///
//     /// This records the (position, value) pair for the permutation argument.
//     /// The position is determined by the current row and register index.
//     fn reg_store<R: Register>(&mut self, value: Self::Variable);
//
//     /// Load a value from a typed register.
//     ///
//     /// This creates a new variable and records a copy constraint via the
//     /// permutation argument. The returned variable is constrained to equal
//     /// the most recently stored value in this register.
//     fn reg_load<R: Register>(&mut self) -> Self::Variable;
//
//     /// Create an explicit copy constraint between two variables.
//     ///
//     /// This adds the pair to the permutation argument, ensuring a = b.
//     fn copy(&mut self, a: &Self::Variable, b: &Self::Variable);
// }
// ```

// ============================================================================
// Constants
// ============================================================================

/// Total number of standard registers.
///
/// This is used to size arrays in the permutation argument implementation.
pub const NUM_STANDARD_REGISTERS: usize = 3;

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_indices_unique() {
        // Ensure all standard registers have unique indices
        assert_ne!(DigestReg::INDEX, UAccReg::INDEX);
        assert_ne!(DigestReg::INDEX, AlphaAccReg::INDEX);
        assert_ne!(UAccReg::INDEX, AlphaAccReg::INDEX);
    }

    #[test]
    fn test_register_indices_sequential() {
        // Ensure indices are sequential starting from 0
        assert_eq!(DigestReg::INDEX, 0);
        assert_eq!(UAccReg::INDEX, 1);
        assert_eq!(AlphaAccReg::INDEX, 2);
    }

    #[test]
    fn test_register_names() {
        assert_eq!(DigestReg::NAME, "digest");
        assert_eq!(UAccReg::NAME, "u_acc");
        assert_eq!(AlphaAccReg::NAME, "alpha_acc");
    }

    #[test]
    fn test_num_standard_registers() {
        assert_eq!(NUM_STANDARD_REGISTERS, 3);
        // Verify it matches the highest index + 1
        assert_eq!(
            NUM_STANDARD_REGISTERS,
            AlphaAccReg::INDEX + 1,
            "NUM_STANDARD_REGISTERS should be highest index + 1"
        );
    }
}
