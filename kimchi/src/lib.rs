#![doc = include_str!("../../README.md")]

#[macro_use]
extern crate num_derive;

pub use cairo;
pub use commitment_dlog;
pub use groupmap;
pub use mina_curves;
pub use o1_utils;
pub use oracle;

pub use commitment_dlog::{commitment::CommitmentCurve, srs::SRS};
pub use groupmap::GroupMap;
pub use oracle::{
    constants::*,
    poseidon::{ArithmeticSponge, Sponge},
    sponge::{DefaultFqSponge, DefaultFrSponge},
};

pub mod alphas;
pub mod bench;
pub mod circuits;
pub mod error;
pub mod linearization;
pub mod plonk_sponge;
pub mod proof;
pub mod prover;
pub mod prover_index;
pub mod verifier;
pub mod verifier_index;

#[cfg(test)]
mod tests;
