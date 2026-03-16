mod fixtures;

// IMPROVEME: move all tests in top-level directory tests
mod and;
#[cfg(feature = "prover")]
mod chunked;
mod ec;
mod endomul;
mod endomul_scalar;
mod foreign_field_add;
mod foreign_field_mul;
#[cfg(feature = "prover")]
mod framework;
mod generic;
mod keccak;
#[cfg(feature = "prover")]
mod lazy_mode;
mod lookup;
mod not;
mod poseidon;
mod range_check;
mod recursion;
mod rot;
#[cfg(feature = "prover")]
mod serde;
mod varbasemul;
mod xor;
