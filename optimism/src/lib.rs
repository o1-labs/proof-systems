// Domain size shared by the keccak evaluations, mips evaluation and main
// program.
pub const DOMAIN_SIZE: usize = 1 << 15;

pub mod cannon;
pub mod cannon_cli;
pub mod keccak;
pub mod mips;
pub mod preimage_oracle;
