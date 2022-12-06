//! This module implements wrapper types around arkworks types.
//! We do this for two reasons:
//! - so that we can implement OCaml-related traits on then, for FFI.
//! - so that we can implement serde traits for serialization.

pub mod bigint256;

#[macro_use]
pub mod fp256;

pub use bigint256::BigInteger256;
