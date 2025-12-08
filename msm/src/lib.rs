use mina_poseidon::{
    constants::PlonkSpongeConstantsKimchi,
    sponge::{DefaultFqSponge, DefaultFrSponge},
};
use poly_commitment::kzg::KZGProof;

pub use logup::{
    Logup, LogupWitness, LookupProof as LogupProof, LookupTable as LogupTable,
    LookupTableID as LogupTableID, LookupTableID,
};

pub mod circuit_design;
pub mod column_env;
pub mod columns;
pub mod expr;
pub mod logup;
/// Instantiations of Logups for the MSM project
// REMOVEME. The different interpreters must define their own tables.
pub mod lookups;
pub mod precomputed_srs;
pub mod proof;
pub mod prover;
pub mod verifier;
pub mod witness;

pub mod fec;
pub mod ffa;
pub mod serialization;
pub mod test;

/// Define the maximum degree we support for the evaluations.
/// For instance, it can be used to split the looked-up functions into partial
/// sums.
const MAX_SUPPORTED_DEGREE: usize = 8;

/// Domain size for the MSM project, equal to the BN254 SRS size.
pub const DOMAIN_SIZE: usize = 1 << 15;

// @volhovm: maybe move these to the FF circuits module later.
/// Bitsize of the foreign field limb representation.
pub const LIMB_BITSIZE: usize = 15;

/// Number of limbs representing one foreign field element (either
/// [`Ff1`] or [`Ff2`]).
pub const N_LIMBS: usize = 17;

pub type BN254 = ark_ec::bn::Bn<ark_bn254::Config>;
pub type BN254G1Affine = <BN254 as ark_ec::pairing::Pairing>::G1Affine;
pub type BN254G2Affine = <BN254 as ark_ec::pairing::Pairing>::G2Affine;

/// The native field we are working with.
pub type Fp = ark_bn254::Fr;

/// The foreign field we are emulating (one of the two)
pub type Ff1 = mina_curves::pasta::Fp;
pub type Ff2 = mina_curves::pasta::Fq;

pub type SpongeParams = PlonkSpongeConstantsKimchi;
pub type BaseSponge = DefaultFqSponge<ark_bn254::g1::Config, SpongeParams, 55>;
pub type ScalarSponge = DefaultFrSponge<Fp, SpongeParams, 55>;
pub type OpeningProof = KZGProof<BN254>;
