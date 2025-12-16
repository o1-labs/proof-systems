//! This crate provides a generic implementation of the Poseidon hash function.
//! It provides a [Sponge](crate::sponge::FqSponge) trait that can be
//! implemented for any field.
//!
//! Some parameters for the Pasta fields are provided in the sub-crate
//! [crate::pasta].
//!
//! To instantiate an object that can be used to generate challenges for the
//! Fiat-Shamir transformation, use the
//! [DefaultFqSponge](crate::sponge::DefaultFqSponge) struct. For instance, to
//! instantiate with the parameters used by the Mina hard-fork called Berkeley,
//! use:
//! ```rust
//! use mina_curves::pasta::{VestaParameters};
//! use mina_poseidon::sponge::DefaultFqSponge;
//! use mina_poseidon::FqSponge;
//! use mina_poseidon::constants::PlonkSpongeConstantsKimchi;
//! use mina_poseidon::pasta::fq_kimchi;
//!
//! let mut sponge = DefaultFqSponge::<VestaParameters, PlonkSpongeConstantsKimchi, { mina_poseidon::pasta::FULL_ROUNDS }>::new(
//!   fq_kimchi::static_params(),
//! );
//! let challenge = sponge.challenge();
//! ```

#![no_std]

pub mod constants;
pub mod dummy_values;
pub mod pasta;
pub mod permutation;
pub mod poseidon;
pub mod sponge;

pub use sponge::FqSponge; // Commonly used so reexported for convenience
