#![doc = include_str!("../README.md")]

#[macro_use]
extern crate num_derive;

pub use commitment_dlog;
pub use groupmap;
pub use mina_curves;
pub use mina_poseidon;
pub use o1_utils;
pub use turshi;

pub mod alphas;
pub mod bench;
pub mod circuits;
pub mod curve;
pub mod error;
pub mod linearization;
pub mod oracles;
pub mod plonk_sponge;
pub mod proof;
pub mod prover;
pub mod prover_index;
pub mod snarky;
pub mod verifier;
pub mod verifier_index;

#[cfg(test)]
mod tests;

/// Handy macro to return the filename and line number of a place in the code.
#[macro_export]
macro_rules! loc {
    () => {{
        format!("{}:{}", file!(), line!())
    }};
}
