mod fixtures;

// IMPROVEME: move all tests in top-level directory tests
#[cfg(feature = "prover")]
mod and;
#[cfg(feature = "prover")]
mod chunked;
#[cfg(feature = "prover")]
mod ec;
#[cfg(feature = "prover")]
mod endomul;
#[cfg(feature = "prover")]
mod endomul_scalar;
#[cfg(feature = "prover")]
mod foreign_field_add;
#[cfg(feature = "prover")]
mod foreign_field_mul;
#[cfg(feature = "prover")]
mod framework;
mod generic;
#[cfg(feature = "prover")]
mod keccak;
#[cfg(feature = "prover")]
mod lazy_mode;
#[cfg(feature = "prover")]
mod lookup;
#[cfg(feature = "prover")]
mod not;
mod poseidon;
#[cfg(feature = "prover")]
mod range_check;
#[cfg(feature = "prover")]
mod recursion;
#[cfg(feature = "prover")]
mod rot;
#[cfg(feature = "prover")]
mod serde;
#[cfg(feature = "prover")]
mod varbasemul;
#[cfg(feature = "prover")]
mod xor;
