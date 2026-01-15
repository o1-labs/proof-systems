//! Core traits for the circuit abstraction layer.
//!
//! This module defines the `StepCircuit` and `CircuitEnv` traits that form the
//! foundation for building zkApps with the Arrabbiata IVC scheme.
//!
//! ## Key Design Principles
//!
//! 1. **Simple trait interface** - Users only need to implement `arity()` and `synthesize()`
//! 2. **Type-safe I/O** - Input/output vectors have explicit size via `arity()`
//! 3. **Clean CircuitEnv abstraction** - Provides typed operations without BigInt
//! 4. **Non-deterministic advice** - Circuits can contain private helper data
//!
//! ## Comparison with Other Folding Implementations
//!
//! ### vs Microsoft Nova (github.com/microsoft/Nova)
//!
//! | Feature | Nova | Arrabbiata |
//! |---------|------|------------|
//! | Constraint system | R1CS (degree-2) | Plonkish (degree ≤ 5) |
//! | Cross-terms | Single T polynomial | One per degree 2..MAX_DEG |
//! | Circuit interface | `StepCircuit<F>` | `StepCircuit<F>` (same) |
//! | Commitment | Pedersen | IPA (compatible) |
//! | Gadgets | Embedded in R1CS | Explicit gadget abstraction |
//!
//! Nova's `StepCircuit` trait signature:
//! ```ignore
//! // Nova uses ConstraintSystem for R1CS synthesis
//! fn synthesize<CS: ConstraintSystem<F>>(
//!     &self, cs: &mut CS, z: &[AllocatedNum<F>]
//! ) -> Result<Vec<AllocatedNum<F>>, SynthesisError>;
//! ```
//!
//! Our `StepCircuit` uses `CircuitEnv` which abstracts over both:
//! - Witness generation (concrete field values)
//! - Constraint generation (symbolic expressions)
//!
//! This is more flexible than R1CS-specific synthesis.
//!
//! ### vs ProtoGalaxy/ProtoStar
//!
//! ProtoGalaxy generalizes folding to arbitrary degree constraints using
//! "virtual folding" - computing cross-terms via Lagrange interpolation.
//! We take a similar approach but compute cross-terms explicitly using
//! the `mvpoly::compute_combined_cross_terms()` function.
//!
//! Key insight: For degree-d constraints, folding requires computing d-1
//! cross-term polynomials. Our MAX_DEGREE=5 means 4 cross-terms per
//! folding step (for powers 2, 3, 4, 5).
//!
//! ### vs Sonobe (github.com/privacy-scaling-explorations/sonobe)
//!
//! Sonobe is a modular folding framework supporting Nova, HyperNova, etc.
//! It uses a similar `FCircuit` trait:
//! ```ignore
//! trait FCircuit<F: PrimeField>: Clone + Debug {
//!     fn new(params: FC::Params) -> Result<Self, Error>;
//!     fn state_len(&self) -> usize;
//!     fn generate_step_constraints(
//!         &self, cs: CS, z_i: Vec<FpVar<F>>
//!     ) -> Result<Vec<FpVar<F>>, SynthesisError>;
//! }
//! ```
//!
//! Our approach differs by:
//! - Supporting gadget composition (EC, Poseidon, etc.)
//! - Using interpreter-based constraint generation
//! - Tight integration with Mina's curve infrastructure
//!
//! ### Design Decisions
//!
//! 1. **Why `CircuitEnv` over R1CS `ConstraintSystem`?**
//!    - Supports higher-degree constraints natively
//!    - Cleaner gadget abstraction (EC, hash as methods)
//!    - Single interface for witness and constraint generation
//!
//! 2. **Why explicit gadgets vs embedding in constraints?**
//!    - Reusable across circuits (Poseidon, EC scalar mul)
//!    - Optimized implementations per gadget
//!    - Future zkVM support (opcodes as gadgets)
//!
//! 3. **Why typed fields vs BigInt?**
//!    - Type safety at compile time
//!    - Better performance (no conversion overhead)
//!    - Cleaner API for circuit authors
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                     StepCircuit<F>                          │
//! │  (User-defined: FibonacciCircuit, SchnorrCircuit, etc.)    │
//! └─────────────────────────────────────────────────────────────┘
//!                              │
//!                              ▼
//! ┌─────────────────────────────────────────────────────────────┐
//! │                     CircuitEnv<F>                           │
//! │  (Clean facade with typed operations)                       │
//! │  - add, sub, mul, constant                                  │
//! │  - assert_eq, assert_zero                                   │
//! │  - ec_add, ec_scalar_mul (gadget operations)                │
//! │  - poseidon_hash                                            │
//! └─────────────────────────────────────────────────────────────┘
//!                              │
//!                              ▼
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    InterpreterEnv                           │
//! │  (Low-level operations, position-based allocation)          │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Example
//!
//! See [`crate::circuits::SquaringGadget`] for a simple example that squares
//! the input at each step:
//!
//! ```
//! use arrabbiata::circuits::{GadgetCircuit, Scalar, SquaringGadget, StepCircuit};
//! use mina_curves::pasta::Fp;
//!
//! // Wrap SquaringGadget as a StepCircuit<Fp, 1>
//! let circuit = GadgetCircuit::new(SquaringGadget, "squaring");
//!
//! // Compute output: 3² = 9
//! let z0 = [Fp::from(3u64)];
//! let z1 = circuit.output(&z0);
//! assert_eq!(z1, [Fp::from(9u64)]);
//!
//! // Chain multiple steps: 3 -> 9 -> 81
//! let z2 = circuit.output(&z1);
//! assert_eq!(z2, [Fp::from(81u64)]);
//! ```
//!
//! For more circuit implementations, see the [`crate::circuits`] module.

use ark_ff::{One, PrimeField, Zero};
use std::fmt::Debug;

/// A clean circuit environment trait with typed operations.
///
/// This trait provides a higher-level interface for building circuits, with:
/// - Type-safe field operations (no BigInt)
/// - Position-based allocation (separates layout from computation)
/// - Constraint assertions
/// - Access to gadgets (EC operations, hash functions)
///
/// ## Position/Variable Pattern
///
/// The design follows the interpreter pattern from o1vm:
/// - **Position**: An abstract location in the circuit (column index + row)
/// - **Variable**: An expression built from positions (symbolic or concrete)
///
/// Workflow:
/// 1. `allocate()` - Get a position for the current row
/// 2. `read_position(pos)` - Read the variable at a position
/// 3. `write_column(pos, value)` - Write a value to a position
///
/// This separates concerns:
/// - Position allocation defines the circuit layout
/// - Variable operations define the computation
///
/// ## Implementation
///
/// It's designed to be implemented by both:
/// - Witness generation environments (Position = column index, Variable = F)
/// - Constraint generation environments (Position = (Column, Row), Variable = Expr<F>)
pub trait CircuitEnv<F: PrimeField> {
    /// A position in the circuit (column + row reference).
    ///
    /// For witness generation: typically a column index `usize`
    /// For constraint generation: typically `(Column, CurrOrNext)`
    type Position: Clone + Copy;

    /// The type of variables in this environment.
    ///
    /// For witness generation: concrete field elements `F`
    /// For constraint generation: symbolic expressions `Expr<F>`
    type Variable: Clone
        + std::ops::Add<Self::Variable, Output = Self::Variable>
        + std::ops::Sub<Self::Variable, Output = Self::Variable>
        + std::ops::Mul<Self::Variable, Output = Self::Variable>
        + Debug
        + Zero
        + One;

    // ========================================================================
    // Position-based allocation (preferred pattern)
    // ========================================================================

    /// Allocate a new position on the current row.
    ///
    /// Returns a position that can be used with `read_position` and `write_column`.
    fn allocate(&mut self) -> Self::Position;

    /// Allocate a new position on the next row.
    ///
    /// Used for constraints that span two rows (e.g., Poseidon output on next row).
    fn allocate_next_row(&mut self) -> Self::Position;

    /// Advance to the next row.
    ///
    /// Call this after completing synthesis for a row to move to the next row.
    /// For gadgets that span multiple rows (like scalar multiplication steps),
    /// this must be called between each step.
    ///
    /// For constraint environments: this is typically a no-op.
    /// For trace environments: advances the current row index.
    fn next_row(&mut self);

    /// Read the variable at the given position.
    ///
    /// For constraint environments: creates a symbolic variable referencing this cell.
    /// For trace environments: returns the value stored at this position.
    fn read_position(&self, pos: Self::Position) -> Self::Variable;

    /// Write a value to the given position and return the variable.
    ///
    /// For constraint environments: the value is used for witness generation.
    /// For trace environments: stores the value in the witness table.
    fn write_column(&mut self, pos: Self::Position, value: Self::Variable) -> Self::Variable;

    // ========================================================================
    // Constants
    // ========================================================================

    /// Create a constant variable from a field element.
    fn constant(&self, value: F) -> Self::Variable;

    /// Return the zero constant.
    fn zero(&self) -> Self::Variable {
        Self::Variable::zero()
    }

    /// Return the one constant.
    fn one(&self) -> Self::Variable {
        Self::Variable::one()
    }

    // ========================================================================
    // Constraints
    // ========================================================================

    /// Assert that a variable equals zero.
    fn assert_zero(&mut self, x: &Self::Variable);

    /// Assert that a variable equals zero, with a name for deduplication.
    ///
    /// When the same constraint is applied to multiple rows (e.g., in repeated
    /// circuits), using named constraints ensures we count unique constraint
    /// expressions rather than total assertions.
    fn assert_zero_named(&mut self, name: &str, x: &Self::Variable) {
        let _ = name; // Default implementation ignores the name
        self.assert_zero(x);
    }

    /// Assert that two variables are equal.
    fn assert_eq(&mut self, x: &Self::Variable, y: &Self::Variable) {
        let diff = x.clone() - y.clone();
        self.assert_zero(&diff);
    }

    /// Assert that two variables are equal, with a name for deduplication.
    fn assert_eq_named(&mut self, name: &str, x: &Self::Variable, y: &Self::Variable) {
        let diff = x.clone() - y.clone();
        self.assert_zero_named(name, &diff);
    }

    // ========================================================================
    // Witness computation helpers
    // ========================================================================

    /// Try to extract the concrete field value from a variable.
    ///
    /// Returns `Some(value)` in witness generation mode (Trace) where variables
    /// are concrete field elements. Returns `None` in constraint generation mode
    /// (ConstraintEnv) where variables are symbolic expressions.
    ///
    /// This is useful for gadgets that need to compute witness values during
    /// synthesis (e.g., computing an inverse for EC addition).
    fn try_as_field(&self, var: &Self::Variable) -> Option<F>;
}

// ============================================================================
// SelectorEnv Trait
// ============================================================================

use crate::{circuits::selector::SelectorTag, column::Gadget};

/// Extension trait for environments that support selector columns.
///
/// This trait provides type-safe access to selector variables for gadget-gated
/// constraints. Each gadget has a unique selector type (e.g., `QECAdd`, `QPoseidonRound<5>`)
/// that maps to a selector column in the circuit.
///
/// ## Usage Pattern
///
/// ```ignore
/// use arrabbiata::circuits::selector::QECAdd;
///
/// // Get selector variable by type (compile-time checked)
/// let q_ec_add = env.selector::<QECAdd>();
///
/// // Gate a constraint by the selector
/// let gated_constraint = q_ec_add.clone() * constraint;
/// env.assert_zero(&gated_constraint);
///
/// // Or use the with_gadget helper for automatic gating
/// env.with_gadget::<QECAdd, _>(|env| {
///     // Constraints here will be auto-gated
///     env.assert_eq(&x, &y);
/// });
/// ```
///
/// ## Implementation Notes
///
/// - For `ConstraintEnv`: returns symbolic `Expr` variables for selector columns
/// - For `Trace`: returns concrete `F::one()` or `F::zero()` based on active gadget
pub trait SelectorEnv<F: PrimeField>: CircuitEnv<F> {
    /// Get the selector variable for a specific gadget type.
    ///
    /// The selector is `1` when the gadget is active for the current row,
    /// and `0` otherwise.
    ///
    /// # Type Parameters
    ///
    /// - `S`: A selector type implementing `SelectorTag` (e.g., `QECAdd`)
    fn selector<S: SelectorTag>(&self) -> Self::Variable;

    /// Get the selector variable by runtime gadget enum.
    ///
    /// This is useful when the gadget type is not known at compile time.
    fn selector_by_gadget(&self, gadget: Gadget) -> Self::Variable;

    /// Get the currently active gadget (if any).
    ///
    /// Returns `None` in constraint environments (symbolic mode).
    /// Returns `Some(gadget)` in trace environments when a gadget is active.
    fn active_gadget(&self) -> Option<Gadget>;

    /// Set the active gadget for the current row.
    ///
    /// This affects which selector returns `1` vs `0` in trace mode.
    fn set_active_gadget(&mut self, gadget: Option<Gadget>);

    /// Execute a closure with the given gadget active.
    ///
    /// This sets the active gadget for the current row. Only one gadget can
    /// be active per row - the selector pattern is mutually exclusive.
    ///
    /// # Panics
    ///
    /// Panics if a gadget is already active (no nesting allowed).
    fn with_gadget<S: SelectorTag, R>(&mut self, f: impl FnOnce(&mut Self) -> R) -> R {
        assert!(
            self.active_gadget().is_none(),
            "Cannot nest with_gadget: gadget {:?} is already active. Only one gadget per row.",
            self.active_gadget()
        );
        self.set_active_gadget(Some(S::GADGET));
        let result = f(self);
        self.set_active_gadget(None);
        result
    }

    /// Assert that a constraint equals zero, gated by the active gadget's selector.
    ///
    /// This is equivalent to: `assert_zero(selector * constraint)`
    /// where `selector` is the selector for the currently active gadget.
    ///
    /// # Panics
    ///
    /// Panics if no gadget is currently active.
    fn assert_gated(&mut self, constraint: &Self::Variable) {
        let gadget = self
            .active_gadget()
            .expect("No gadget active; use with_gadget() or set_active_gadget()");
        let selector = self.selector_by_gadget(gadget);
        let gated = selector * constraint.clone();
        self.assert_zero(&gated);
    }
}

/// A trait for step circuits that define a single step of incremental computation.
///
/// This is the main abstraction for user-defined zkApps. Each step takes a public
/// input array `z_i` of size `ARITY` and produces an output array `z_{i+1}`
/// of the same size.
///
/// # Type Parameters
///
/// * `F` - The prime field for circuit values
/// * `ARITY` - The number of public inputs/outputs (compile-time constant)
///
/// # Type Safety
///
/// The `ARITY` const generic ensures that:
/// - Input/output sizes are checked at compile time
/// - Out-of-bounds access to `z[i]` is a compile error
/// - No runtime arity mismatches possible
///
/// # Example
///
/// ```
/// use arrabbiata::circuit::{StepCircuit, CircuitEnv};
/// use ark_ff::PrimeField;
///
/// // Fibonacci circuit with arity 2 (two state variables)
/// #[derive(Clone, Debug)]
/// struct FibonacciCircuit;
///
/// impl<F: PrimeField> StepCircuit<F, 2> for FibonacciCircuit {
///     const NAME: &'static str = "FibonacciCircuit";
///
///     fn synthesize<E: CircuitEnv<F>>(
///         &self,
///         _env: &mut E,
///         z: &[E::Variable; 2],  // Compile-time checked!
///     ) -> [E::Variable; 2] {
///         let a = z[0].clone();
///         let b = z[1].clone();
///         [b.clone(), a + b]
///     }
///
///     fn output(&self, z: &[F; 2]) -> [F; 2] {
///         [z[1], z[0] + z[1]]
///     }
/// }
/// ```
pub trait StepCircuit<F: PrimeField, const ARITY: usize>: Clone + Debug + Send + Sync {
    /// The name of this circuit for identification and debugging.
    const NAME: &'static str;

    /// Synthesize the circuit for one step of computation.
    ///
    /// # Arguments
    ///
    /// * `env` - The circuit environment for building constraints/witness
    /// * `z` - Input values for this step (fixed-size array of length `ARITY`)
    ///
    /// # Returns
    ///
    /// Output values for this step (fixed-size array of length `ARITY`)
    fn synthesize<E: CircuitEnv<F> + SelectorEnv<F>>(
        &self,
        env: &mut E,
        z: &[E::Variable; ARITY],
    ) -> [E::Variable; ARITY];

    /// Compute the output of a step directly (for verification/testing).
    fn output(&self, z: &[F; ARITY]) -> [F; ARITY];

    /// Returns the number of rows used per fold.
    ///
    /// For simple circuits, this is 1. For circuits that amortize computation
    /// (like RepeatedFibonacciCircuit), this can be larger.
    ///
    /// The constraint expressions are the same for all rows; this just
    /// determines how many rows of witness satisfy those constraints per fold.
    fn num_rows(&self) -> usize {
        1
    }
}

// ============================================================================
// Constraint Environment (for testing circuits with expressions)
// ============================================================================

use crate::column::{Column, E};
use kimchi::circuits::{
    expr::{ConstantTerm::Literal, ExprInner, Operations, Variable},
    gate::CurrOrNext,
};
use std::collections::HashMap;

/// A constraint environment for testing circuits.
///
/// This environment uses the same expression type (`E<F>`) as the main
/// constraint system, allowing us to track actual constraints and compute
/// their degrees accurately.
///
/// # Example
///
/// ```
/// use arrabbiata::circuit::{ConstraintEnv, CircuitEnv, StepCircuit};
/// use arrabbiata::circuits::{GadgetCircuit, TrivialGadget};
/// use mina_curves::pasta::Fp;
///
/// let circuit = GadgetCircuit::new(TrivialGadget, "trivial");
/// let mut env = ConstraintEnv::<Fp>::new();
/// let z = env.make_input_vars::<1>();
/// let _ = circuit.synthesize(&mut env, &z);
///
/// // TrivialGadget has no constraints
/// assert_eq!(env.num_constraints(), 0);
/// ```
pub struct ConstraintEnv<F: PrimeField> {
    /// Counter for allocating witness variables on the current row
    witness_idx: usize,
    /// Counter for allocating witness variables on the next row
    witness_idx_next_row: usize,
    /// Anonymous constraints (from assert_zero)
    constraints: Vec<E<F>>,
    /// Named constraints (from assert_zero_named) - deduplicated by name
    named_constraints: HashMap<String, E<F>>,
    /// Currently active gadget (for SelectorEnv tracking)
    active_gadget: Option<Gadget>,
}

impl<F: PrimeField> ConstraintEnv<F> {
    /// Create a new constraint environment.
    pub fn new() -> Self {
        Self {
            witness_idx: 0,
            witness_idx_next_row: 0,
            constraints: Vec::new(),
            named_constraints: HashMap::new(),
            active_gadget: None,
        }
    }

    /// Get the number of unique constraints (anonymous + named).
    pub fn num_constraints(&self) -> usize {
        self.constraints.len() + self.named_constraints.len()
    }

    /// Get the number of anonymous constraints.
    pub fn num_anonymous_constraints(&self) -> usize {
        self.constraints.len()
    }

    /// Get the number of named constraints.
    pub fn num_named_constraints(&self) -> usize {
        self.named_constraints.len()
    }

    /// Get the number of witness variables allocated.
    ///
    /// This counts the total number of `allocate()` calls during synthesis.
    /// In the actual prover, each witness allocation corresponds to filling
    /// a cell in the witness table.
    pub fn num_witness_allocations(&self) -> usize {
        self.witness_idx
    }

    /// Get all constraints (anonymous + named).
    pub fn all_constraints(&self) -> Vec<&E<F>> {
        self.constraints
            .iter()
            .chain(self.named_constraints.values())
            .collect()
    }

    /// Get the anonymous constraints.
    pub fn constraints(&self) -> &[E<F>] {
        &self.constraints
    }

    /// Get the named constraints.
    pub fn named_constraints(&self) -> &HashMap<String, E<F>> {
        &self.named_constraints
    }

    /// Get all constraint degrees.
    pub fn constraint_degrees(&self) -> Vec<usize> {
        self.all_constraints()
            .iter()
            .map(|c| c.degree(1, 0) as usize)
            .collect()
    }

    /// Get the maximum degree among all constraints.
    pub fn max_degree(&self) -> usize {
        self.all_constraints()
            .iter()
            .map(|c| c.degree(1, 0) as usize)
            .max()
            .unwrap_or(0)
    }

    /// Check that all constraints have degree at most MAX_DEGREE.
    pub fn check_degrees(&self) -> Result<(), String> {
        for (i, c) in self.all_constraints().iter().enumerate() {
            let deg = c.degree(1, 0) as usize;
            if deg > crate::MAX_DEGREE {
                return Err(format!(
                    "Constraint {} has degree {} but max allowed is {}",
                    i,
                    deg,
                    crate::MAX_DEGREE
                ));
            }
        }
        Ok(())
    }

    /// Create an array of input variables of size ARITY.
    ///
    /// Input variables are treated as degree-1 expressions.
    pub fn make_input_vars<const ARITY: usize>(&mut self) -> [E<F>; ARITY] {
        std::array::from_fn(|i| {
            let col = Column::X(i);
            E::Atom(ExprInner::Cell(Variable {
                col,
                row: CurrOrNext::Curr,
            }))
        })
    }
}

impl<F: PrimeField> Default for ConstraintEnv<F> {
    fn default() -> Self {
        Self::new()
    }
}

impl<F: PrimeField> CircuitEnv<F> for ConstraintEnv<F> {
    /// Position is (Column, CurrOrNext) for symbolic expressions.
    type Position = (Column, CurrOrNext);
    type Variable = E<F>;

    fn allocate(&mut self) -> Self::Position {
        assert!(
            self.witness_idx < NUMBER_OF_COLUMNS,
            "Maximum number of columns reached ({NUMBER_OF_COLUMNS})"
        );
        let col = Column::X(self.witness_idx);
        self.witness_idx += 1;
        (col, CurrOrNext::Curr)
    }

    fn allocate_next_row(&mut self) -> Self::Position {
        assert!(
            self.witness_idx_next_row < NUMBER_OF_COLUMNS,
            "Maximum number of columns reached ({NUMBER_OF_COLUMNS})"
        );
        let col = Column::X(self.witness_idx_next_row);
        self.witness_idx_next_row += 1;
        (col, CurrOrNext::Next)
    }

    fn next_row(&mut self) {
        // For constraint environments, advance allocation indices similar to Trace.
        // After next_row(), what was "next row" becomes "current row".
        self.witness_idx = self.witness_idx_next_row;
        self.witness_idx_next_row = 0;
    }

    fn read_position(&self, pos: Self::Position) -> Self::Variable {
        let (col, row) = pos;
        E::Atom(ExprInner::Cell(Variable { col, row }))
    }

    fn write_column(&mut self, pos: Self::Position, _value: Self::Variable) -> Self::Variable {
        // For constraint environments, we ignore the value and just return the position variable.
        // The value is only used during witness generation.
        self.read_position(pos)
    }

    fn constant(&self, value: F) -> Self::Variable {
        let v_inner = Operations::from(Literal(value));
        E::constant(v_inner)
    }

    fn assert_zero(&mut self, x: &Self::Variable) {
        let degree = x.degree(1, 0);
        assert!(
            (degree as usize) <= crate::MAX_DEGREE,
            "Constraint has degree {} but max allowed is {}",
            degree,
            crate::MAX_DEGREE
        );
        self.constraints.push(x.clone());
    }

    fn assert_zero_named(&mut self, name: &str, x: &Self::Variable) {
        let degree = x.degree(1, 0);
        assert!(
            (degree as usize) <= crate::MAX_DEGREE,
            "Constraint '{}' has degree {} but max allowed is {}",
            name,
            degree,
            crate::MAX_DEGREE
        );
        // Check if this name already exists
        if let Some(existing) = self.named_constraints.get(name) {
            // Same name must have same expression (for deduplication in repeated circuits)
            // We check structural equality by comparing the debug representation
            assert!(
                format!("{:?}", existing) == format!("{:?}", x),
                "Constraint name '{}' already exists with a different expression.\n\
                 Existing: {:?}\n\
                 New: {:?}",
                name,
                existing,
                x
            );
            // Same constraint, already registered - skip
        } else {
            self.named_constraints.insert(name.to_string(), x.clone());
        }
    }

    fn try_as_field(&self, _var: &Self::Variable) -> Option<F> {
        // In constraint mode, variables are symbolic expressions, not concrete values
        None
    }
}

impl<F: PrimeField> SelectorEnv<F> for ConstraintEnv<F> {
    fn selector<S: SelectorTag>(&self) -> Self::Variable {
        E::Atom(ExprInner::Cell(Variable {
            col: Column::Selector(S::GADGET),
            row: CurrOrNext::Curr,
        }))
    }

    fn selector_by_gadget(&self, gadget: Gadget) -> Self::Variable {
        E::Atom(ExprInner::Cell(Variable {
            col: Column::Selector(gadget),
            row: CurrOrNext::Curr,
        }))
    }

    fn active_gadget(&self) -> Option<Gadget> {
        self.active_gadget
    }

    fn set_active_gadget(&mut self, gadget: Option<Gadget>) {
        self.active_gadget = gadget;
    }
}

// ============================================================================
// Trace (for building execution traces)
// ============================================================================

use crate::NUMBER_OF_COLUMNS;

/// A trace environment for building execution traces.
///
/// This environment uses concrete field values and builds a witness table
/// (trace) that can be used by the prover. It also validates constraints
/// at runtime by checking that they evaluate to zero.
///
/// The trace has a fixed number of columns ([`NUMBER_OF_COLUMNS`]) matching
/// the Arrabbiata circuit layout. The number of rows is determined by the
/// domain size, which is typically derived from the SRS size.
///
/// Each row can have allocations for both the current row and the next row
/// (for constraints that span two rows, such as permutation arguments).
///
/// # Example
///
/// ```
/// use arrabbiata::circuit::{Trace, CircuitEnv, StepCircuit};
/// use arrabbiata::circuits::{GadgetCircuit, SquaringGadget};
/// use mina_curves::pasta::Fp;
///
/// let circuit = GadgetCircuit::new(SquaringGadget, "squaring");
/// let domain_size = 1 << 8; // 256 rows
/// let mut env = Trace::<Fp>::new(domain_size);
///
/// // Run one step
/// let z = env.make_input_vars([Fp::from(3u64)]);
/// let output = circuit.synthesize(&mut env, &z);
/// env.next_row();
///
/// // Domain size is fixed
/// assert_eq!(env.num_rows(), domain_size);
/// ```
// TODO: Parallelization opportunity for witness generation
//
// The current Trace implementation generates witnesses sequentially row-by-row.
// For circuits with independent row computations (e.g., repeated gadgets like
// Poseidon hashing or scalar multiplication), witness generation could be
// parallelized using rayon:
//
// 1. **Row-level parallelism**: When gadgets are independent across rows,
//    compute multiple rows in parallel using `par_iter_mut()` on the witness.
//
// 2. **Gadget-level parallelism**: For composite gadgets that internally use
//    multiple independent sub-gadgets (e.g., SchnorrVerifyGadget computes
//    two scalar multiplications), these could run in parallel.
//
// 3. **Batch witness generation**: Pre-allocate the full witness table and
//    use work-stealing to fill rows as inputs become available.
//
// Considerations:
// - Row dependencies must be tracked (some gadgets read from previous rows)
// - Memory allocation patterns may need adjustment for cache efficiency
// - Thread synchronization overhead vs computation cost tradeoff
//
// See also: `rayon::prelude::*` for parallel iterators
pub struct Trace<F: PrimeField> {
    /// Domain size (number of rows, determined by SRS size)
    domain_size: usize,
    /// Current row index we are operating on
    current_row_idx: usize,
    /// Current column position for current-row witness allocation
    idx_var: usize,
    /// Current column position for next-row witness allocation
    idx_var_next_row: usize,
    /// The witness table: witness[row][col] = value
    witness: Vec<Vec<F>>,
    /// Whether constraint failures should panic (true) or be collected (false)
    panic_on_failure: bool,
    /// Failed constraints (if panic_on_failure is false)
    failed_constraints: Vec<String>,
    /// Currently active gadget (for SelectorEnv tracking)
    active_gadget: Option<Gadget>,
}

impl<F: PrimeField> Trace<F> {
    /// Create a new trace environment with the given domain size.
    ///
    /// The domain size determines the number of rows in the witness table,
    /// typically derived from the SRS size (domain_size = 2^srs_log_size).
    pub fn new(domain_size: usize) -> Self {
        assert!(domain_size > 0, "Domain size must be at least 1");
        let witness = (0..domain_size)
            .map(|_| vec![F::zero(); NUMBER_OF_COLUMNS])
            .collect();
        Self {
            domain_size,
            current_row_idx: 0,
            idx_var: 0,
            idx_var_next_row: 0,
            witness,
            panic_on_failure: true,
            failed_constraints: Vec::new(),
            active_gadget: None,
        }
    }

    /// Create a trace environment that collects failures instead of panicking.
    pub fn new_non_panicking(domain_size: usize) -> Self {
        assert!(domain_size > 0, "Domain size must be at least 1");
        let witness = (0..domain_size)
            .map(|_| vec![F::zero(); NUMBER_OF_COLUMNS])
            .collect();
        Self {
            domain_size,
            current_row_idx: 0,
            idx_var: 0,
            idx_var_next_row: 0,
            witness,
            panic_on_failure: false,
            failed_constraints: Vec::new(),
            active_gadget: None,
        }
    }

    /// Start a new row in the witness table.
    ///
    /// Call this after completing synthesis for one step to advance
    /// to the next row. The current column index is set to the next-row
    /// column index (to avoid overwriting values already placed via
    /// `allocate_next_row()`), and the next-row column index is reset.
    ///
    /// # Panics
    ///
    /// Panics if we've already reached the last row.
    pub fn next_row(&mut self) {
        assert!(
            self.current_row_idx + 1 < self.domain_size,
            "Cannot advance past the last row (row {} of {})",
            self.current_row_idx,
            self.domain_size
        );
        self.current_row_idx += 1;
        // Set idx_var to idx_var_next_row to avoid overwriting values
        // that were placed on this row via allocate_next_row()
        self.idx_var = self.idx_var_next_row;
        self.idx_var_next_row = 0;
    }

    /// Get the domain size (number of rows).
    pub fn domain_size(&self) -> usize {
        self.domain_size
    }

    /// Get the number of rows in the witness table.
    pub fn num_rows(&self) -> usize {
        self.domain_size
    }

    /// Get a reference to the witness table.
    pub fn witness(&self) -> &[Vec<F>] {
        &self.witness
    }

    /// Get a specific cell from the witness table.
    pub fn get(&self, row: usize, col: usize) -> Option<&F> {
        self.witness.get(row).and_then(|r| r.get(col))
    }

    /// Set a specific cell in the current row.
    pub fn set(&mut self, col: usize, value: F) {
        assert!(col < NUMBER_OF_COLUMNS, "Column index out of bounds");
        self.witness[self.current_row_idx][col] = value;
    }

    /// Set a specific cell in the next row.
    ///
    /// # Panics
    ///
    /// Panics if we're at the last row (no next row exists).
    pub fn set_next_row(&mut self, col: usize, value: F) {
        let next_row_idx = self.current_row_idx + 1;
        assert!(
            next_row_idx < self.domain_size,
            "Cannot write to next row: already at the last row (row {} of {})",
            self.current_row_idx,
            self.domain_size
        );
        assert!(col < NUMBER_OF_COLUMNS, "Column index out of bounds");
        self.witness[next_row_idx][col] = value;
    }

    /// Check if any constraint failures occurred.
    pub fn has_failures(&self) -> bool {
        !self.failed_constraints.is_empty()
    }

    /// Get the list of failed constraints.
    pub fn failed_constraints(&self) -> &[String] {
        &self.failed_constraints
    }

    /// Create input variables with the given values.
    ///
    /// This is a convenience method for setting up the initial state.
    /// The values are copied to the first columns of the current row.
    ///
    /// Note: This does NOT assume input arity equals output arity.
    /// The circuit can have different input and output sizes.
    pub fn make_input_vars<const N: usize>(&mut self, values: [F; N]) -> [F; N] {
        for (i, v) in values.iter().enumerate() {
            self.set(i, *v);
        }
        self.idx_var = N;
        values
    }

    /// Create input variables from a slice (dynamic size).
    ///
    /// This is useful when the input size is not known at compile time.
    pub fn make_input_vars_dynamic(&mut self, values: &[F]) -> Vec<F> {
        for (i, v) in values.iter().enumerate() {
            self.set(i, *v);
        }
        self.idx_var = values.len();
        values.to_vec()
    }

    /// Get the current row index.
    pub fn current_row(&self) -> usize {
        self.current_row_idx
    }

    /// Get the current column index for current-row allocations.
    pub fn current_col(&self) -> usize {
        self.idx_var
    }

    /// Get the current column index for next-row allocations.
    pub fn current_col_next_row(&self) -> usize {
        self.idx_var_next_row
    }

    /// Reset the trace to the initial state (clears all values, resets to row 0).
    pub fn reset(&mut self) {
        self.current_row_idx = 0;
        self.idx_var = 0;
        self.idx_var_next_row = 0;
        for row in &mut self.witness {
            for cell in row {
                *cell = F::zero();
            }
        }
        self.failed_constraints.clear();
    }
}

impl<F: PrimeField> CircuitEnv<F> for Trace<F> {
    /// Position is (column index, CurrOrNext) for concrete witness.
    type Position = (usize, CurrOrNext);
    // PrimeField already implements Clone, Add, Sub, Mul, Debug, Zero, One
    type Variable = F;

    fn allocate(&mut self) -> Self::Position {
        assert!(
            self.idx_var < NUMBER_OF_COLUMNS,
            "Maximum number of columns reached ({NUMBER_OF_COLUMNS})"
        );
        let col = self.idx_var;
        self.idx_var += 1;
        (col, CurrOrNext::Curr)
    }

    fn allocate_next_row(&mut self) -> Self::Position {
        assert!(
            self.idx_var_next_row < NUMBER_OF_COLUMNS,
            "Maximum number of columns reached ({NUMBER_OF_COLUMNS})"
        );
        let col = self.idx_var_next_row;
        self.idx_var_next_row += 1;
        (col, CurrOrNext::Next)
    }

    fn next_row(&mut self) {
        // Delegate to the existing method on Trace
        Trace::next_row(self);
    }

    fn read_position(&self, pos: Self::Position) -> Self::Variable {
        let (col, row) = pos;
        let row_idx = match row {
            CurrOrNext::Curr => self.current_row_idx,
            CurrOrNext::Next => self.current_row_idx + 1,
        };
        self.witness[row_idx][col]
    }

    fn write_column(&mut self, pos: Self::Position, value: Self::Variable) -> Self::Variable {
        let (col, row) = pos;
        let row_idx = match row {
            CurrOrNext::Curr => self.current_row_idx,
            CurrOrNext::Next => {
                let next_row = self.current_row_idx + 1;
                assert!(
                    next_row < self.domain_size,
                    "Cannot write to next row: already at the last row (row {} of {})",
                    self.current_row_idx,
                    self.domain_size
                );
                next_row
            }
        };
        self.witness[row_idx][col] = value;
        value
    }

    fn constant(&self, value: F) -> Self::Variable {
        value
    }

    fn assert_zero(&mut self, x: &Self::Variable) {
        if !x.is_zero() {
            let msg = format!("Constraint failed: expected 0, got {:?}", x);
            if self.panic_on_failure {
                panic!("{}", msg);
            } else {
                self.failed_constraints.push(msg);
            }
        }
    }

    fn assert_zero_named(&mut self, name: &str, x: &Self::Variable) {
        if !x.is_zero() {
            let msg = format!("Constraint '{}' failed: expected 0, got {:?}", name, x);
            if self.panic_on_failure {
                panic!("{}", msg);
            } else {
                self.failed_constraints.push(msg);
            }
        }
    }

    fn try_as_field(&self, var: &Self::Variable) -> Option<F> {
        // In witness mode, variables ARE concrete field elements
        Some(*var)
    }
}

impl<F: PrimeField> SelectorEnv<F> for Trace<F> {
    fn selector<S: SelectorTag>(&self) -> Self::Variable {
        // In trace mode, return 1 if this gadget is active, 0 otherwise
        if self.active_gadget == Some(S::GADGET) {
            F::one()
        } else {
            F::zero()
        }
    }

    fn selector_by_gadget(&self, gadget: Gadget) -> Self::Variable {
        // In trace mode, return 1 if this gadget is active, 0 otherwise
        if self.active_gadget == Some(gadget) {
            F::one()
        } else {
            F::zero()
        }
    }

    fn active_gadget(&self) -> Option<Gadget> {
        self.active_gadget
    }

    fn set_active_gadget(&mut self, gadget: Option<Gadget>) {
        self.active_gadget = gadget;
    }
}

#[cfg(test)]
mod trace_tests {
    use super::*;
    use mina_curves::pasta::Fp;

    const TEST_DOMAIN_SIZE: usize = 16;

    #[test]
    fn test_trace_basic() {
        let mut env = Trace::<Fp>::new(TEST_DOMAIN_SIZE);

        // Create input
        let z = env.make_input_vars([Fp::from(5u64)]);
        assert_eq!(z[0], Fp::from(5u64));

        // Verify input was stored
        assert_eq!(env.get(0, 0), Some(&Fp::from(5u64)));
    }

    #[test]
    fn test_trace_alloc() {
        let mut env = Trace::<Fp>::new(TEST_DOMAIN_SIZE);

        // Allocate a witness using position-based API
        let w = {
            let pos = env.allocate();
            env.write_column(pos, Fp::from(42u64))
        };
        assert_eq!(w, Fp::from(42u64));

        // Verify it was stored
        assert_eq!(env.get(0, 0), Some(&Fp::from(42u64)));
    }

    #[test]
    fn test_trace_operations() {
        let env = Trace::<Fp>::new(TEST_DOMAIN_SIZE);

        let a = env.constant(Fp::from(3u64));
        let b = env.constant(Fp::from(4u64));

        // Add
        let sum = a + b;
        assert_eq!(sum, Fp::from(7u64));

        // Mul
        let prod = a * b;
        assert_eq!(prod, Fp::from(12u64));

        // Sub
        let diff = b - a;
        assert_eq!(diff, Fp::from(1u64));
    }

    #[test]
    fn test_trace_constraint_pass() {
        let mut env = Trace::<Fp>::new(TEST_DOMAIN_SIZE);

        let zero = env.constant(Fp::from(0u64));
        env.assert_zero(&zero); // Should not panic
    }

    #[test]
    #[should_panic(expected = "Constraint failed")]
    fn test_trace_constraint_fail() {
        let mut env = Trace::<Fp>::new(TEST_DOMAIN_SIZE);

        let nonzero = env.constant(Fp::from(1u64));
        env.assert_zero(&nonzero); // Should panic
    }

    #[test]
    fn test_trace_non_panicking() {
        let mut env = Trace::<Fp>::new_non_panicking(TEST_DOMAIN_SIZE);

        let nonzero = env.constant(Fp::from(1u64));
        env.assert_zero(&nonzero); // Should not panic

        assert!(env.has_failures());
        assert_eq!(env.failed_constraints().len(), 1);
    }

    #[test]
    fn test_trace_multi_row() {
        let mut env = Trace::<Fp>::new(TEST_DOMAIN_SIZE);

        // First row
        let _ = env.make_input_vars([Fp::from(1u64), Fp::from(2u64)]);
        env.next_row();

        // Second row
        let _ = env.make_input_vars([Fp::from(3u64), Fp::from(4u64)]);

        assert_eq!(env.num_rows(), TEST_DOMAIN_SIZE);
        assert_eq!(env.get(0, 0), Some(&Fp::from(1u64)));
        assert_eq!(env.get(1, 0), Some(&Fp::from(3u64)));
    }

    #[test]
    fn test_trace_dynamic_inputs() {
        let mut env = Trace::<Fp>::new(TEST_DOMAIN_SIZE);

        // Create inputs of different sizes
        let inputs3 = env.make_input_vars([Fp::from(1u64), Fp::from(2u64), Fp::from(3u64)]);
        assert_eq!(inputs3.len(), 3);

        env.next_row();
        let inputs2 = env.make_input_vars([Fp::from(4u64), Fp::from(5u64)]);
        assert_eq!(inputs2.len(), 2);

        // Verify dynamic inputs work too
        env.next_row();
        let dynamic_inputs = env.make_input_vars_dynamic(&[Fp::from(6u64), Fp::from(7u64)]);
        assert_eq!(dynamic_inputs.len(), 2);

        // Verify the trace
        assert_eq!(env.get(0, 2), Some(&Fp::from(3u64)));
        assert_eq!(env.get(1, 1), Some(&Fp::from(5u64)));
        assert_eq!(env.get(2, 0), Some(&Fp::from(6u64)));
    }

    #[test]
    fn test_trace_next_row_allocation() {
        let mut env = Trace::<Fp>::new(TEST_DOMAIN_SIZE);

        // Allocate on current row using position-based API
        let a = {
            let pos = env.allocate();
            env.write_column(pos, Fp::from(1u64))
        };
        assert_eq!(a, Fp::from(1u64));
        assert_eq!(env.get(0, 0), Some(&Fp::from(1u64)));

        // Allocate on next row using position-based API
        let b = {
            let pos = env.allocate_next_row();
            env.write_column(pos, Fp::from(2u64))
        };
        assert_eq!(b, Fp::from(2u64));
        assert_eq!(env.get(1, 0), Some(&Fp::from(2u64)));

        // Allocate another on next row
        let c = {
            let pos = env.allocate_next_row();
            env.write_column(pos, Fp::from(3u64))
        };
        assert_eq!(c, Fp::from(3u64));
        assert_eq!(env.get(1, 1), Some(&Fp::from(3u64)));

        // Current row should be unchanged
        assert_eq!(env.current_row(), 0);
        assert_eq!(env.current_col(), 1);
        assert_eq!(env.current_col_next_row(), 2);

        // Now move to next row and continue
        env.next_row();
        assert_eq!(env.current_row(), 1);
        // idx_var should be set to idx_var_next_row (2) to avoid overwriting
        assert_eq!(env.current_col(), 2);
        assert_eq!(env.current_col_next_row(), 0);

        // Previous next-row allocations should still be there
        assert_eq!(env.get(1, 0), Some(&Fp::from(2u64)));
        assert_eq!(env.get(1, 1), Some(&Fp::from(3u64)));
    }

    #[test]
    fn test_trace_next_row_preserves_values() {
        // Test that values allocated on next row are not overwritten
        // when we move to that row and continue allocating
        let mut env = Trace::<Fp>::new(TEST_DOMAIN_SIZE);

        // Allocate output values on next row (simulating circuit outputs)
        {
            let pos = env.allocate_next_row();
            env.write_column(pos, Fp::from(100u64)) // col 0
        };
        {
            let pos = env.allocate_next_row();
            env.write_column(pos, Fp::from(200u64)) // col 1
        };
        {
            let pos = env.allocate_next_row();
            env.write_column(pos, Fp::from(300u64)) // col 2
        };

        // Move to next row
        env.next_row();

        // idx_var should start at 3 (where idx_var_next_row was)
        assert_eq!(env.current_col(), 3);

        // Allocate a new value - should go to col 3, not overwrite col 0
        let new_val = {
            let pos = env.allocate();
            env.write_column(pos, Fp::from(400u64))
        };
        assert_eq!(new_val, Fp::from(400u64));
        assert_eq!(env.current_col(), 4);

        // Verify all values are preserved
        assert_eq!(env.get(1, 0), Some(&Fp::from(100u64)));
        assert_eq!(env.get(1, 1), Some(&Fp::from(200u64)));
        assert_eq!(env.get(1, 2), Some(&Fp::from(300u64)));
        assert_eq!(env.get(1, 3), Some(&Fp::from(400u64)));
    }

    #[test]
    fn test_trace_next_row_no_allocations() {
        // When no next-row allocations, idx_var should start at 0
        let mut env = Trace::<Fp>::new(TEST_DOMAIN_SIZE);

        // Allocate on current row only using position-based API
        {
            let pos = env.allocate();
            env.write_column(pos, Fp::from(1u64))
        };
        {
            let pos = env.allocate();
            env.write_column(pos, Fp::from(2u64))
        };
        assert_eq!(env.current_col(), 2);
        assert_eq!(env.current_col_next_row(), 0);

        // Move to next row
        env.next_row();

        // idx_var should be 0 since no next-row allocations were made
        assert_eq!(env.current_col(), 0);
        assert_eq!(env.current_col_next_row(), 0);
    }

    #[test]
    #[should_panic(expected = "Cannot write to next row")]
    fn test_trace_next_row_at_end_panics() {
        let mut env = Trace::<Fp>::new(2); // Only 2 rows

        env.next_row(); // Move to last row (row 1)
                        // Now trying to write to "next row" (row 2) should fail
        let pos = env.allocate_next_row();
        env.write_column(pos, Fp::from(1u64));
    }

    #[test]
    #[should_panic(expected = "Cannot advance past the last row")]
    fn test_trace_next_row_past_end_panics() {
        let mut env = Trace::<Fp>::new(2); // Only 2 rows

        env.next_row(); // Move to last row (row 1)
        env.next_row(); // This should panic
    }

    #[test]
    fn test_selector_env_trace() {
        use crate::circuits::selector::{QApp, QECAdd};

        let mut env = Trace::<Fp>::new(TEST_DOMAIN_SIZE);

        // Initially no gadget is active
        assert_eq!(env.active_gadget(), None);
        assert_eq!(env.selector::<QApp>(), Fp::zero());
        assert_eq!(env.selector::<QECAdd>(), Fp::zero());

        // Set App gadget as active
        env.set_active_gadget(Some(Gadget::App));
        assert_eq!(env.active_gadget(), Some(Gadget::App));
        assert_eq!(env.selector::<QApp>(), Fp::one());
        assert_eq!(env.selector::<QECAdd>(), Fp::zero());

        // Set EC Add gadget as active
        env.set_active_gadget(Some(Gadget::EllipticCurveAddition));
        assert_eq!(env.active_gadget(), Some(Gadget::EllipticCurveAddition));
        assert_eq!(env.selector::<QApp>(), Fp::zero());
        assert_eq!(env.selector::<QECAdd>(), Fp::one());

        // Clear active gadget
        env.set_active_gadget(None);
        assert_eq!(env.active_gadget(), None);
        assert_eq!(env.selector::<QApp>(), Fp::zero());
        assert_eq!(env.selector::<QECAdd>(), Fp::zero());
    }

    #[test]
    fn test_selector_env_with_gadget() {
        use crate::circuits::selector::QApp;

        let mut env = Trace::<Fp>::new(TEST_DOMAIN_SIZE);

        // with_gadget should temporarily set the active gadget
        let result = env.with_gadget::<QApp, _>(|env| {
            assert_eq!(env.active_gadget(), Some(Gadget::App));
            assert_eq!(env.selector::<QApp>(), Fp::one());
            42u64
        });

        // After with_gadget, the active gadget should be restored
        assert_eq!(env.active_gadget(), None);
        assert_eq!(result, 42u64);
    }
}

#[cfg(test)]
mod selector_env_tests {
    use super::*;
    use crate::circuits::selector::{QApp, QECAdd, QPoseidonRound};
    use mina_curves::pasta::Fp;

    #[test]
    fn test_constraint_env_selector() {
        let env = ConstraintEnv::<Fp>::new();

        // Selectors return symbolic expressions
        let q_app = env.selector::<QApp>();
        let q_ec_add = env.selector::<QECAdd>();

        // They should be different expressions
        assert_ne!(format!("{:?}", q_app), format!("{:?}", q_ec_add));

        // They should reference selector columns
        let q_app_str = format!("{:?}", q_app);
        assert!(
            q_app_str.contains("Selector") && q_app_str.contains("App"),
            "Expected selector column, got: {}",
            q_app_str
        );
    }

    #[test]
    fn test_constraint_env_selector_by_gadget() {
        let env = ConstraintEnv::<Fp>::new();

        // selector<S>() and selector_by_gadget(S::GADGET) should produce the same expression
        let q_app_typed = env.selector::<QApp>();
        let q_app_runtime = env.selector_by_gadget(Gadget::App);

        assert_eq!(
            format!("{:?}", q_app_typed),
            format!("{:?}", q_app_runtime),
            "selector<S>() and selector_by_gadget(S::GADGET) should be identical"
        );
    }

    #[test]
    fn test_constraint_env_poseidon_round_selectors() {
        let env = ConstraintEnv::<Fp>::new();

        // Different Poseidon rounds should have different selectors
        let q_round_0 = env.selector::<QPoseidonRound<0>>();
        let q_round_5 = env.selector::<QPoseidonRound<5>>();
        let q_round_55 = env.selector::<QPoseidonRound<55>>();

        assert_ne!(format!("{:?}", q_round_0), format!("{:?}", q_round_5));
        assert_ne!(format!("{:?}", q_round_0), format!("{:?}", q_round_55));
        assert_ne!(format!("{:?}", q_round_5), format!("{:?}", q_round_55));
    }

    #[test]
    fn test_constraint_env_with_gadget() {
        let mut env = ConstraintEnv::<Fp>::new();

        // Initially no active gadget
        assert_eq!(env.active_gadget(), None);

        // with_gadget sets the active gadget for the row
        env.with_gadget::<QApp, _>(|env| {
            assert_eq!(env.active_gadget(), Some(Gadget::App));
        });

        // After with_gadget, active gadget is cleared
        assert_eq!(env.active_gadget(), None);

        // Can use a different gadget for next row
        env.with_gadget::<QECAdd, _>(|env| {
            assert_eq!(env.active_gadget(), Some(Gadget::EllipticCurveAddition));
        });

        assert_eq!(env.active_gadget(), None);
    }

    #[test]
    #[should_panic(expected = "Cannot nest with_gadget")]
    fn test_constraint_env_with_gadget_no_nesting() {
        let mut env = ConstraintEnv::<Fp>::new();

        // Nesting with_gadget should panic - only one gadget per row
        env.with_gadget::<QApp, _>(|env| {
            env.with_gadget::<QECAdd, _>(|_env| {
                // Should not reach here
            });
        });
    }
}
