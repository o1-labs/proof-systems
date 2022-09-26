//! This module implements wrapper types around arkworks types.
//! We do this for two reasons:
//! - so that we can implement OCaml-related traits on then, for FFI.
//! - so that we can implement serde traits for serialization.

#[macro_use]
pub mod fields;

pub use fields::{fp::Fp, fq::Fq};
