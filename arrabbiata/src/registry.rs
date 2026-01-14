//! Circuit registry for managing and selecting circuits.
//!
//! The `CircuitRegistry` allows registering circuits by name and retrieving
//! metadata about them. This is used by the CLI to select which circuit to run.
//!
//! ## Example
//!
//! ```
//! use arrabbiata::registry::{CircuitRegistry, CircuitInfo};
//!
//! let registry = CircuitRegistry::default();
//!
//! // Get all registered circuits
//! for (name, info) in registry.circuits() {
//!     println!("{}: {} (arity {})", name, info.description, info.arity);
//! }
//!
//! // Get a specific circuit
//! if let Some(info) = registry.get("fibonacci") {
//!     println!("Fibonacci has arity {}", info.arity);
//! }
//! ```

use std::collections::HashMap;

/// Information about a registered circuit.
#[derive(Debug, Clone)]
pub struct CircuitInfo {
    /// Human-readable description of the circuit.
    pub description: String,
    /// The arity (number of input/output elements) of the circuit.
    pub arity: usize,
    /// Maximum constraint degree of the circuit.
    pub max_degree: usize,
    /// Number of constraints in the circuit.
    pub num_constraints: usize,
    /// Number of rows used per fold. Determines minimum SRS size.
    pub rows_per_fold: usize,
}

impl CircuitInfo {
    /// Create a new circuit info with 1 row per fold (default for simple circuits).
    pub fn new(description: &str, arity: usize, max_degree: usize, num_constraints: usize) -> Self {
        Self {
            description: description.to_string(),
            arity,
            max_degree,
            num_constraints,
            rows_per_fold: 1,
        }
    }

    /// Create a new circuit info with a specified number of rows per fold.
    pub fn with_rows(
        description: &str,
        arity: usize,
        max_degree: usize,
        num_constraints: usize,
        rows_per_fold: usize,
    ) -> Self {
        Self {
            description: description.to_string(),
            arity,
            max_degree,
            num_constraints,
            rows_per_fold,
        }
    }

    /// Get the minimum SRS log2 size required for this circuit.
    pub fn min_srs_log2_size(&self) -> usize {
        // SRS size must be >= rows_per_fold, rounded up to next power of 2
        let mut log2 = 0;
        let mut size = 1;
        while size < self.rows_per_fold {
            size *= 2;
            log2 += 1;
        }
        // Minimum is 8 for the verifier circuit
        log2.max(8)
    }
}

/// A registry for circuit types.
///
/// The registry maps circuit names to their metadata.
#[derive(Debug, Clone)]
pub struct CircuitRegistry {
    circuits: HashMap<String, CircuitInfo>,
}

impl CircuitRegistry {
    /// Create an empty circuit registry.
    pub fn new() -> Self {
        Self {
            circuits: HashMap::new(),
        }
    }

    /// Register a circuit with the given name and info.
    pub fn register(&mut self, name: &str, info: CircuitInfo) -> &mut Self {
        self.circuits.insert(name.to_string(), info);
        self
    }

    /// Get information about a circuit by name.
    pub fn get(&self, name: &str) -> Option<&CircuitInfo> {
        self.circuits.get(name)
    }

    /// Check if a circuit is registered.
    pub fn contains(&self, name: &str) -> bool {
        self.circuits.contains_key(name)
    }

    /// Get all registered circuits.
    pub fn circuits(&self) -> impl Iterator<Item = (&String, &CircuitInfo)> {
        self.circuits.iter()
    }

    /// Get the names of all registered circuits.
    pub fn names(&self) -> impl Iterator<Item = &String> {
        self.circuits.keys()
    }

    /// Get the number of registered circuits.
    pub fn len(&self) -> usize {
        self.circuits.len()
    }

    /// Check if the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.circuits.is_empty()
    }
}

impl Default for CircuitRegistry {
    /// Create a registry with all built-in circuits registered.
    fn default() -> Self {
        let mut registry = Self::new();

        registry
            .register(
                "trivial",
                CircuitInfo::new("Identity circuit: z_{i+1} = z_i", 1, 1, 1),
            )
            .register(
                "squaring",
                CircuitInfo::new("Squaring circuit: z_{i+1} = z_i^2", 1, 2, 1),
            )
            .register(
                "repeated-squaring",
                CircuitInfo::with_rows(
                    "Repeated squaring: 2^15 squarings per fold (requires --srs-size 15)",
                    1,
                    2,
                    1,     // Same constraint repeated across rows
                    32768, // 2^15 rows per fold
                ),
            )
            .register(
                "cubic",
                CircuitInfo::new("Cubic circuit: z_{i+1} = z_i^3 + z_i + 5", 1, 3, 1),
            )
            .register(
                "square-cubic",
                CircuitInfo::new(
                    "Composed circuit: x -> x^6 + x^2 + 5",
                    1,
                    3, // max degree from cubic
                    2, // 1 from squaring + 1 from cubic
                ),
            )
            .register(
                "fibonacci",
                CircuitInfo::new("Fibonacci sequence: (x, y) -> (y, x + y)", 2, 1, 2),
            )
            .register(
                "repeated-fibonacci",
                CircuitInfo::with_rows(
                    "Repeated Fibonacci: 2^15 steps per fold (requires --srs-size 15)",
                    2,
                    1,
                    2,     // Same 2 constraints repeated across rows
                    32768, // 2^15 rows per fold
                ),
            )
            .register(
                "counter",
                CircuitInfo::new("Counter circuit: z_{i+1} = z_i + 1", 1, 1, 1),
            )
            .register(
                "minroot",
                CircuitInfo::new("MinRoot VDF: computes 5th roots", 2, 5, 1),
            )
            .register(
                "hashchain",
                CircuitInfo::new("Hash chain: z_{i+1} = hash(z_i)", 1, 5, 1),
            );

        registry
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_default() {
        let registry = CircuitRegistry::default();

        assert!(registry.contains("squaring"));
        assert!(registry.contains("fibonacci"));
        assert!(registry.contains("cubic"));
        assert!(registry.contains("square-cubic"));
        assert!(!registry.contains("nonexistent"));

        let squaring = registry.get("squaring").unwrap();
        assert_eq!(squaring.arity, 1);
        assert_eq!(squaring.max_degree, 2);
        assert_eq!(squaring.num_constraints, 1);
    }

    #[test]
    fn test_registry_register() {
        let mut registry = CircuitRegistry::new();
        registry.register("custom", CircuitInfo::new("Custom circuit", 3, 4, 5));

        assert!(registry.contains("custom"));
        let custom = registry.get("custom").unwrap();
        assert_eq!(custom.arity, 3);
        assert_eq!(custom.max_degree, 4);
        assert_eq!(custom.num_constraints, 5);
    }

    #[test]
    fn test_registry_len() {
        let registry = CircuitRegistry::default();
        assert_eq!(registry.len(), 10);

        let empty = CircuitRegistry::new();
        assert_eq!(empty.len(), 0);
        assert!(empty.is_empty());
    }

    #[test]
    fn test_repeated_circuit_srs_size() {
        let registry = CircuitRegistry::default();

        // Repeated circuits require larger SRS
        let repeated_sq = registry.get("repeated-squaring").unwrap();
        assert_eq!(repeated_sq.rows_per_fold, 32768);
        assert_eq!(repeated_sq.min_srs_log2_size(), 15);

        let repeated_fib = registry.get("repeated-fibonacci").unwrap();
        assert_eq!(repeated_fib.rows_per_fold, 32768);
        assert_eq!(repeated_fib.min_srs_log2_size(), 15);

        // Simple circuits use 1 row
        let squaring = registry.get("squaring").unwrap();
        assert_eq!(squaring.rows_per_fold, 1);
        assert_eq!(squaring.min_srs_log2_size(), 8); // Minimum for verifier circuit
    }
}
