//! Circuit registry using heterogeneous lists (HList).
//!
//! This module provides a type-safe, compile-time circuit registry built on HList.
//! Circuits are registered by their `TypedGadget` implementation which provides
//! all necessary metadata (NAME, DESCRIPTION, ARITY, ROWS).
//!
//! ## Example
//!
//! ```
//! use arrabbiata::registry::{circuits, CircuitList};
//! use arrabbiata::circuits::{SquaringGadget, FibonacciGadget};
//!
//! // Build a registry at compile time
//! let registry = circuits()
//!     .register(SquaringGadget::new())
//!     .register(FibonacciGadget::new());
//!
//! // Get all circuit names
//! let names = registry.names();
//! assert!(names.contains(&"squaring"));
//! assert!(names.contains(&"fibonacci"));
//!
//! // Check if a circuit exists
//! assert!(registry.contains("squaring"));
//! ```

use core::fmt::Debug;
use mina_curves::pasta::Fp;

use crate::circuits::gadget::TypedGadget;

// ============================================================================
// CircuitInfo - Runtime representation
// ============================================================================

/// Runtime information about a circuit.
///
/// This is extracted from a circuit implementing `TypedGadget`.
#[derive(Debug, Clone)]
pub struct CircuitInfo {
    /// Circuit name.
    pub name: &'static str,
    /// Human-readable description.
    pub description: &'static str,
    /// The arity (number of input/output elements).
    pub arity: usize,
    /// Number of rows per fold.
    pub rows: usize,
}

impl CircuitInfo {
    /// Get the minimum SRS log2 size required for this circuit.
    pub fn min_srs_log2_size(&self) -> usize {
        let mut log2 = 0;
        let mut size = 1;
        while size < self.rows {
            size *= 2;
            log2 += 1;
        }
        log2.max(8) // Minimum 8 for verifier circuit
    }
}

// ============================================================================
// HList Types for Circuit Registry
// ============================================================================

/// Empty circuit list (base case).
#[derive(Clone, Debug, Default)]
pub struct CNil;

/// Non-empty circuit list: head circuit followed by tail.
#[derive(Clone, Debug)]
pub struct CCons<H, T> {
    pub head: H,
    pub tail: T,
}

// ============================================================================
// CircuitList Trait
// ============================================================================

/// Trait for heterogeneous lists of circuits.
pub trait CircuitList: Clone + Debug {
    /// Number of circuits in the list.
    const LEN: usize;

    /// Get the length of this list.
    fn len(&self) -> usize {
        Self::LEN
    }

    /// Check if the list is empty.
    fn is_empty(&self) -> bool {
        Self::LEN == 0
    }

    /// Register a new circuit (prepends to the list).
    fn register<G>(self, circuit: G) -> CCons<G, Self>
    where
        Self: Sized,
    {
        CCons {
            head: circuit,
            tail: self,
        }
    }

    /// Get all circuit names.
    fn names(&self) -> Vec<&'static str>;

    /// Check if a circuit with the given name exists.
    fn contains(&self, name: &str) -> bool {
        self.names().contains(&name)
    }

    /// Get all circuit info.
    fn infos(&self) -> Vec<CircuitInfo>;

    /// Get info for a specific circuit by name.
    fn get(&self, name: &str) -> Option<CircuitInfo> {
        self.infos().into_iter().find(|info| info.name == name)
    }

    /// Print all circuits (for CLI --list-circuits).
    fn print_all(&self) {
        println!("Available circuits:\n");
        for info in self.infos() {
            println!("  {}", info.name);
            println!("    {}", info.description);
            println!(
                "    arity: {}, rows: {}, min-srs: {}",
                info.arity,
                info.rows,
                info.min_srs_log2_size()
            );
            println!();
        }
    }
}

impl CircuitList for CNil {
    const LEN: usize = 0;

    fn names(&self) -> Vec<&'static str> {
        Vec::new()
    }

    fn infos(&self) -> Vec<CircuitInfo> {
        Vec::new()
    }
}

impl<H, T> CircuitList for CCons<H, T>
where
    H: TypedGadget<Fp>,
    T: CircuitList,
{
    const LEN: usize = 1 + T::LEN;

    fn names(&self) -> Vec<&'static str> {
        let mut result = vec![H::NAME];
        result.extend(self.tail.names());
        result
    }

    fn infos(&self) -> Vec<CircuitInfo> {
        let info = CircuitInfo {
            name: H::NAME,
            description: H::DESCRIPTION,
            arity: H::ARITY,
            rows: H::ROWS,
        };
        let mut result = vec![info];
        result.extend(self.tail.infos());
        result
    }
}

// ============================================================================
// Builder Helper
// ============================================================================

/// Start building a circuit registry.
pub fn circuits() -> CNil {
    CNil
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuits::gadgets::{CubicGadget, FibonacciGadget, SquaringGadget, TrivialGadget};

    #[test]
    fn test_empty_registry() {
        let registry = circuits();
        assert_eq!(registry.len(), 0);
        assert!(registry.is_empty());
        assert!(registry.names().is_empty());
    }

    #[test]
    fn test_register_circuits() {
        let registry = circuits()
            .register(SquaringGadget::new())
            .register(FibonacciGadget::new());

        assert_eq!(registry.len(), 2);
        assert!(!registry.is_empty());

        let names = registry.names();
        assert!(names.contains(&"fibonacci"));
        assert!(names.contains(&"squaring"));
    }

    #[test]
    fn test_contains() {
        let registry = circuits()
            .register(SquaringGadget::new())
            .register(CubicGadget::new());

        assert!(registry.contains("squaring"));
        assert!(registry.contains("cubic"));
        assert!(!registry.contains("fibonacci"));
        assert!(!registry.contains("nonexistent"));
    }

    #[test]
    fn test_get_info() {
        let registry = circuits()
            .register(SquaringGadget::new())
            .register(FibonacciGadget::new());

        let squaring = registry.get("squaring").unwrap();
        assert_eq!(squaring.name, "squaring");
        assert_eq!(squaring.arity, 1);
        assert_eq!(squaring.rows, 1);

        let fibonacci = registry.get("fibonacci").unwrap();
        assert_eq!(fibonacci.name, "fibonacci");
        assert_eq!(fibonacci.arity, 2);
        assert_eq!(fibonacci.rows, 1);

        assert!(registry.get("nonexistent").is_none());
    }

    #[test]
    fn test_infos() {
        let registry = circuits()
            .register(TrivialGadget::new())
            .register(SquaringGadget::new())
            .register(CubicGadget::new());

        let infos = registry.infos();
        assert_eq!(infos.len(), 3);

        // Order is reversed (push prepends)
        assert_eq!(infos[0].name, "cubic");
        assert_eq!(infos[1].name, "squaring");
        assert_eq!(infos[2].name, "trivial");
    }

    #[test]
    fn test_min_srs_log2_size() {
        let info = CircuitInfo {
            name: "test",
            description: "Test circuit",
            arity: 1,
            rows: 1,
        };
        assert_eq!(info.min_srs_log2_size(), 8); // Minimum

        let info_large = CircuitInfo {
            name: "large",
            description: "Large circuit",
            arity: 1,
            rows: 32768, // 2^15
        };
        assert_eq!(info_large.min_srs_log2_size(), 15);
    }
}
