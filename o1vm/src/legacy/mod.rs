//! This submodule provides the legacy flavor/interface of the o1vm, and is not
//! supposed to be used anymore.
//!
//! This o1vm flavor was supposed to use the [folding](folding) library defined
//! in [folding](folding), which consists of reducing all constraints to degree
//! 2, in addition to the `ivc` library defined in this monorepo to support long
//! traces.
//! The goal of this flavor was to support the curve `bn254`. For the time
//! being, the project has been stopped in favor of the pickles version defined
//! in [crate::pickles] and we do not aim to provide any support for now.
//!
//! You can still run the legacy flavor by using:
//!
//! ```bash
//! O1VM_FLAVOR=legacy bash run-code.sh
//! ```

use ark_ec::bn::Bn;
use mina_poseidon::{
    constants::PlonkSpongeConstantsKimchi,
    sponge::{DefaultFqSponge, DefaultFrSponge},
};
use poly_commitment::kzg::KZGProof;

/// Scalar field of BN254
pub type Fp = ark_bn254::Fr;
/// Elliptic curve group of BN254
pub type Curve = ark_bn254::G1Affine;
pub type BaseSponge = DefaultFqSponge<ark_bn254::g1::Parameters, SpongeParams>;
pub type ScalarSponge = DefaultFrSponge<Fp, SpongeParams>;
pub type SpongeParams = PlonkSpongeConstantsKimchi;
pub type OpeningProof = KZGProof<Bn<ark_bn254::Parameters>>;

pub mod folding;
pub mod proof;
pub mod trace;
