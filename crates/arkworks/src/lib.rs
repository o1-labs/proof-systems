//! This module contains wrapper types to Arkworks types.
//! To use Arkwork types in OCaml, you have to convert to these types,
//! and convert back from them to use them in Rust.
//!
//! For example:
//!
//! ```
//! use marlin_plonk_bindings::arkworks::CamlBiginteger256;
//! use ark_ff::BigInteger256;
//!
//! #[ocaml::func]
//! pub fn caml_add(x: CamlBigInteger256, y: CamlBigInteger256) -> CamlBigInteger256 {
//!    let x: BigInteger256 = x.into();
//!    let y: BigInteger256 = y.into();
//!    (x + y).into()
//! }
//! ```
//!

mod bigint_256;
mod group_affine;
mod group_projective;
mod pasta_fp;
mod pasta_fq;

pub use bigint_256::WasmBigInteger256;
pub use group_affine::{WasmGPallas, WasmGVesta};
pub use group_projective::{WasmPallasGProjective, WasmVestaGProjective};
pub use pasta_fp::WasmPastaFp;
pub use pasta_fq::WasmPastaFq;
