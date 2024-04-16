/// Domain size shared by the Keccak evaluations, MIPS evaluation and main
/// program.
pub const DOMAIN_SIZE: usize = 1 << 15;

/// Modules mimicking the defined structures used by Cannon CLI.
pub mod cannon;

/// A CLI mimicking the Cannon CLI.
pub mod cannon_cli;

#[cfg(feature = "bn254")]
/// Integration with folding. Contains common trait implementations to be used by each circuit.
pub mod folding;

/// Implementation of Keccak used by the zkVM.
pub mod keccak;

/// Instantiation of the lookups for the VM project.
pub mod lookups;

/// MIPS interpreter.
pub mod mips;

/// Preimage oracle interface used by the zkVM.
pub mod preimage_oracle;

/// Proof system of the zkVM.
pub mod proof;

/// The RAM lookup argument.
pub mod ramlookup;

use kimchi::circuits::expr::{ConstantExpr, Expr};
use kimchi_msm::{columns::Column, witness::Witness};
use lookups::Lookup;
use std::collections::HashMap;

pub use ramlookup::{LookupMode as RAMLookupMode, RAMLookup};

/// Type to represent a constraint on the individual columns of the execution
/// trace.
/// As a reminder, a constraint can be formally defined as a multi-variate
/// polynomial over a finite field. The variables of the polynomial are defined
/// as `kimchi_msm::columns::Column``.
/// The `expression` framework defined in `kimchi::circuits::expr` is used to
/// describe the multi-variate polynomials.
/// For instance, a vanilla 3-wires PlonK constraint can be defined using the
/// multi-variate polynomial of degree 2
/// `P(X, Y, Z) = q_x X + q_y Y + q_m X Y + q_o Z + q_c`
/// To represent this multi-variate polynomial using the expression framework,
/// we would use 3 different columns.
pub(crate) type E<F> = Expr<ConstantExpr<F>, Column>;

pub struct Circuit<const N: usize, SELECTOR, F> {
    /// The domain size of the circuit
    pub domain_size: usize,
    /// The witness for a given selector
    pub witness: HashMap<SELECTOR, Witness<N, Vec<F>>>,
    /// The vector of constraints for a given selector
    pub constraints: HashMap<SELECTOR, Vec<E<F>>>,
    /// The vector of lookups for a given selector
    pub lookups: HashMap<SELECTOR, Vec<Lookup<E<F>>>>,
}

pub trait CircuitTrait<const N: usize, SELECTOR, F, Env> {
    /// Create a new circuit
    fn new(domain_size: usize, env: &mut Env) -> Self;

    /// Add a witness row to the circuit
    fn push_row(&mut self, step: SELECTOR, row: &[F; N]);

    /// Pads the rows of one selector until reaching the domain size if needed.
    /// Returns true if padding was performed, false otherwise.
    fn pad(&mut self, step: SELECTOR) -> bool;

    /// Pads the rows of the witnesses until reaching the domain size
    fn pad_witnesses(&mut self);

    /// Resets the witness after folding
    fn reset(&mut self, step: SELECTOR);
}
