/// Modules mimicking the defined structures used by Cannon CLI.
pub mod cannon;

pub mod cli;

/// A module to load ELF files.
pub mod elf_loader;

pub mod interpreters;

/// Pickles flavor of the o1vm.
pub mod pickles;

/// Instantiation of the lookups for the VM project.
pub mod lookups;

/// Preimage oracle interface used by the zkVM.
pub mod preimage_oracle;

/// The RAM lookup argument.
pub mod ramlookup;

pub mod utils;

pub mod test_preimage_read;

use crate::pickles::column_env::RelationColumnType;
use kimchi::circuits::{
    berkeley_columns::BerkeleyChallengeTerm,
    expr::{ConstantExpr, Expr},
};
use kimchi_msm::columns::Column;
pub use ramlookup::{LookupMode as RAMLookupMode, RAMLookup};

/// Type to represent a constraint on the individual columns of the execution
/// trace.
/// As a reminder, a constraint can be formally defined as a multi-variate
/// polynomial over a finite field. The variables of the polynomial are defined
/// as `kimchi_msm::columns::Column`.
/// The `expression` framework defined in `kimchi::circuits::expr` is used to
/// describe the multi-variate polynomials.
/// For instance, a vanilla 3-wires PlonK constraint can be defined using the
/// multi-variate polynomial of degree 2
/// `P(X, Y, Z) = q_x X + q_y Y + q_m X Y + q_o Z + q_c`
/// To represent this multi-variate polynomial using the expression framework,
/// we would use 3 different columns.
pub type E<F> = Expr<ConstantExpr<F, BerkeleyChallengeTerm>, Column<RelationColumnType>>;
