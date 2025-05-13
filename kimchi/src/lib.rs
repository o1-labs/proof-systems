#![doc = include_str!("../README.md")]

pub use groupmap;
pub use mina_curves;
pub use mina_poseidon;
pub use o1_utils;
pub use poly_commitment;
pub use turshi;

pub mod alphas;
pub mod bench;
pub mod circuits;
pub mod curve;
pub mod error;
pub mod lagrange_basis_evaluations;
pub mod linearization;
pub mod oracles;
pub mod plonk_sponge;
pub mod proof;
pub mod prover;
pub mod prover_index;
pub mod verifier;
pub mod verifier_index;

#[cfg(test)]
mod tests;

/// Handy macro to return the filename and line number of a place in the code.
#[macro_export]
macro_rules! loc {
    () => {{
        ::std::borrow::Cow::Owned(format!("{}:{}", file!(), line!()))
    }};
}
