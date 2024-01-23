/// Domain size shared by the Keccak evaluations, MIPS evaluation and main
/// program.
pub const DOMAIN_SIZE: usize = 1 << 15;

/// Modules mimicking the defined structures used by Cannon CLI.
pub mod cannon;

/// A CLI mimicking the Cannon CLI.
pub mod cannon_cli;

/// Implementation of Keccak used by the zkVM.
pub mod keccak;

/// MIPS interpreter.
pub mod mips;

/// Preimage oracle interface used by the zkVM.
pub mod preimage_oracle;
