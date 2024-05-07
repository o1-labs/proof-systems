//! This module provides examples on how to use the different submodules of the library.
//! The examples are meant to be run with the `cargo nextest` command.
//! The user is encouraged to read the code and understand the different steps of the protocol.
//! The examples are built over a generic type of columns and selectors.
//! The user is encouraged to start reading this module and then move to the
//! modules specialised for the different folding implementations.
//!
//! The examples are generic enough to be reused externally. The users can copy the
//! code and adapt it to their needs. The generic structures are defined in the
//! `checker` module.

use mina_poseidon::{constants::PlonkSpongeConstantsKimchi, sponge::DefaultFqSponge};

// 0. We start by defining the field and the curve that will be used in the
// constraint system, in addition to the sponge that will be used to generate
// challenges.
pub type Fp = ark_bn254::Fr;
pub type Curve = ark_bn254::G1Affine;
pub type SpongeParams = PlonkSpongeConstantsKimchi;
pub type BaseSponge = DefaultFqSponge<ark_bn254::g1::Parameters, SpongeParams>;

pub mod example;
pub mod example_decomposable_folding;
pub mod example_quadriticization;
