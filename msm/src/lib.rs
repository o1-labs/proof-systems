use mina_poseidon::{
    constants::PlonkSpongeConstantsKimchi,
    sponge::{DefaultFqSponge, DefaultFrSponge},
};
use poly_commitment::pairing_proof::PairingProof;

pub mod columns;
pub mod proof;
pub mod prover;
pub mod verifier;

pub const DOMAIN_SIZE: usize = 1 << 15;

pub type BN254 = ark_ec::bn::Bn<ark_bn254::Parameters>;

/// The native field we are working with
pub type Fp = ark_bn254::Fr;

pub type SpongeParams = PlonkSpongeConstantsKimchi;
pub type BaseSponge = DefaultFqSponge<ark_bn254::g1::Parameters, SpongeParams>;
pub type ScalarSponge = DefaultFrSponge<Fp, SpongeParams>;
pub type OpeningProof = PairingProof<BN254>;
