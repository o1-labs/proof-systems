/// Domain size shared by the Keccak evaluations, MIPS evaluation and main
/// program.
pub const DOMAIN_SIZE: usize = 1 << 15;

/// Modules mimicking the defined structures used by Cannon CLI.
pub mod cannon;

/// A CLI mimicking the Cannon CLI.
pub mod cannon_cli;

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

use kimchi::{
    circuits::expr::{ConstantExpr, Expr},
    curve::KimchiCurve,
};
use kimchi_msm::{columns::Column, proof::ProofInputs, witness::Witness, LookupTableID};
use lookups::Lookup;
use std::{collections::HashMap, hash::Hash};

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

pub struct Circuit<const N: usize, G: KimchiCurve, ID: LookupTableID, SELECTOR> {
    /// The proof inputs for folding instances.
    /// Includes witness evaluations and mvlookups.
    pub(crate) proof_inputs: HashMap<SELECTOR, ProofInputs<N, G, ID>>,
    /// The vector of constraints for a given selector
    pub(crate) constraints: HashMap<SELECTOR, Vec<E<G::ScalarField>>>,
    /// The vector of lookups for a given selector
    pub(crate) lookups: HashMap<SELECTOR, Vec<Lookup<E<G::ScalarField>>>>,
}

pub trait CircuitTrait<const N: usize, G: KimchiCurve, ID: LookupTableID, SELECTOR, Env> {
    /// Create a new circuit
    fn new(domain_size: usize, env: &mut Env) -> Self;

    /// Add a witness row to the circuit
    fn push_row(&mut self, step: SELECTOR, row: &[G::ScalarField; N]);

    /// Pads the rows of the witnesses until reaching the domain size
    fn pad_rows(&mut self);
}
