//! Mina Poseidon hasher
//!
//! An implementation of Mina's hasher based on the poseidon arithmetic sponge

use alloc::{vec, vec::Vec};

use core::marker::PhantomData;

use crate::DomainParameter;
use mina_curves::pasta::Fp;
use mina_poseidon::{
    constants::{PlonkSpongeConstantsKimchi, PlonkSpongeConstantsLegacy, SpongeConstants},
    pasta,
    poseidon::{ArithmeticSponge, ArithmeticSpongeParams, Sponge, SpongeState},
};

use super::{domain_prefix_to_field, Hashable, Hasher};

/// Poseidon hasher context
//
//  The arithmetic sponge parameters are large and costly to initialize,
//  so we only want to do this once and then re-use the Poseidon context
//  for many hashes. Also, following approach of the mina code we store
//  a backup of the initialized sponge state for efficient reuse.
pub struct Poseidon<SC: SpongeConstants, H: Hashable> {
    sponge: ArithmeticSponge<Fp, SC>,
    sponge_state: SpongeState,
    /// The state of the sponge
    pub state: Vec<Fp>,
    phantom: PhantomData<H>,
}

impl<SC: SpongeConstants, H: Hashable> Poseidon<SC, H> {
    fn new(domain_param: H::D, sponge_params: &'static ArithmeticSpongeParams<Fp>) -> Self {
        let mut poseidon = Poseidon::<SC, H> {
            sponge: ArithmeticSponge::<Fp, SC>::new(sponge_params),
            sponge_state: SpongeState::Absorbed(0),
            state: vec![],
            phantom: PhantomData,
        };

        poseidon.init(domain_param);

        poseidon
    }
}

/// Poseidon hasher type with legacy plonk sponge constants
pub type PoseidonHasherLegacy<H> = Poseidon<PlonkSpongeConstantsLegacy, H>;

/// Create a legacy hasher context
pub(crate) fn new_legacy<H: Hashable>(domain_param: H::D) -> PoseidonHasherLegacy<H> {
    Poseidon::<PlonkSpongeConstantsLegacy, H>::new(domain_param, pasta::fp_legacy::static_params())
}

/// Poseidon hasher type with experimental kimchi plonk sponge constants
pub type PoseidonHasherKimchi<H> = Poseidon<PlonkSpongeConstantsKimchi, H>;

/// Create an experimental kimchi hasher context
pub(crate) fn new_kimchi<H: Hashable>(domain_param: H::D) -> PoseidonHasherKimchi<H> {
    Poseidon::<PlonkSpongeConstantsKimchi, H>::new(domain_param, pasta::fp_kimchi::static_params())
}

impl<SC: SpongeConstants, H: Hashable> Hasher<H> for Poseidon<SC, H>
where
    H::D: DomainParameter,
{
    fn reset(&mut self) -> &mut dyn Hasher<H> {
        // Efficient reset
        self.sponge.sponge_state = self.sponge_state.clone();
        self.sponge.state.clone_from(&self.state);

        self
    }

    fn init(&mut self, domain_param: H::D) -> &mut dyn Hasher<H> {
        // Set sponge initial state and save it so the hasher context can be
        // reused efficiently
        // N.B. Mina sets the sponge's initial state by hashing the input type's
        // domain bytes
        self.sponge.reset();

        if let Some(domain_string) = H::domain_string(domain_param) {
            self.sponge
                .absorb(&[domain_prefix_to_field::<Fp>(domain_string)]);
            self.sponge.squeeze();
        }

        // Save initial state for efficient reset
        self.sponge_state = self.sponge.sponge_state.clone();
        self.state.clone_from(&self.sponge.state);

        self
    }

    fn update(&mut self, input: &H) -> &mut dyn Hasher<H> {
        self.sponge.absorb(&input.to_roinput().to_fields());

        self
    }

    fn digest(&mut self) -> Fp {
        let output = self.sponge.squeeze();
        self.sponge.reset();
        output
    }
}
