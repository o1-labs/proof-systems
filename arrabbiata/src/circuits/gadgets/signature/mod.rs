//! Signature circuit gadgets.
//!
//! This module contains typed gadgets for signature verification.
//!
//! ## Schnorr Signatures
//!
//! The [`schnorr`] module provides Schnorr signature verification compatible
//! with Mina's signature scheme using Poseidon hashing.

mod schnorr;

pub use schnorr::{
    verify_schnorr_signature, SchnorrHashGadget, SchnorrHashInput, SchnorrHashOutput,
    SchnorrSignature, SchnorrVerifyGadget, SchnorrVerifyInput, SchnorrVerifyOutput,
};
