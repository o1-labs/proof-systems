#![doc = include_str!("../README.md")]

#[macro_use]
extern crate num_derive;

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
pub mod precomputed_srs;
pub mod proof;
pub mod prover;
pub mod prover_index;
pub mod snarky;
pub mod verifier;
pub mod verifier_index;

#[cfg(test)]
mod tests;

#[cfg(feature = "wasm_log")]
use wasm_bindgen::prelude::wasm_bindgen;

#[cfg(feature = "wasm_log")]
#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
}

#[cfg(feature = "wasm_log")]
#[macro_export]
macro_rules! wasm_log {
    ($($t:tt)*) => (crate::log(&format_args!($($t)*).to_string()))
}

#[cfg(not(feature = "wasm_log"))]
#[macro_export]
macro_rules! wasm_log {
    ($($t:tt)*) => ()
}
