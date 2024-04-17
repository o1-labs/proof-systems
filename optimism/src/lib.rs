/// Domain size shared by the Keccak evaluations, MIPS evaluation and main
/// program.
pub const DOMAIN_SIZE: usize = 1 << 15;

/// Defines a circuit environment used for testing / demo purposes
pub mod circuit;

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
use kimchi_msm::columns::Column;

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
