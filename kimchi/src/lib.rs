#![doc = include_str!("../README.md")]
#![cfg_attr(not(feature = "std"), no_std)]
// Allow non_local_definitions from derive macros (proptest_derive, ocaml)
// until upstream crates are updated.
// See https://github.com/o1-labs/mina-rust/issues/1954
#![allow(non_local_definitions)]

extern crate alloc;

// Re-export alloc types so all modules have access in no_std mode.
// This is used instead of patching every file individually.
#[allow(unused_imports)]
#[doc(hidden)]
mod prelude {
    pub use alloc::{
        borrow::ToOwned,
        boxed::Box,
        format,
        string::{String, ToString},
        vec,
        vec::Vec,
    };
}

// Pull prelude into scope for all modules in this crate.
#[allow(unused_imports)]
use prelude::*;

pub use groupmap;
pub use mina_curves;
pub use mina_poseidon;
pub use o1_utils;
pub use poly_commitment;

pub mod alphas;
#[cfg(feature = "prover")]
pub mod bench;
pub mod circuits;
pub mod curve;
pub mod error;
#[cfg(feature = "prover")]
pub mod lagrange_basis_evaluations;
pub mod linearization;
pub mod oracles;
pub mod plonk_sponge;
pub mod proof;
#[cfg(feature = "prover")]
pub mod prover;
#[cfg(feature = "prover")]
pub mod prover_index;
pub mod verifier;
pub mod verifier_index;

#[cfg(all(test, feature = "prover"))]
mod tests;

/// Handy macro to return the filename and line number of a place in the code.
#[macro_export]
macro_rules! loc {
    () => {{
        ::alloc::borrow::Cow::Owned(format!("{}:{}", file!(), line!()))
    }};
}
