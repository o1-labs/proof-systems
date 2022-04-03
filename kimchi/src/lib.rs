#![doc = include_str!("../../README.md")]

#[macro_use]
extern crate num_derive;

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
