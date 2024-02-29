/// Domain size shared by the Keccak evaluations, MIPS evaluation and main
/// program.
pub const DOMAIN_SIZE: usize = 1 << 15;

/// Modules mimicking the defined structures used by Cannon CLI.
pub mod cannon;

/// A CLI mimicking the Cannon CLI.
pub mod cannon_cli;

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

/// Generic definition of a zkvm witness.
pub mod witness;

pub use ramlookup::{Lookup as RAMLookup, LookupMode as RAMLookupMode};
