pub mod blob;
pub mod cli;
pub mod commitment;
pub mod diff;
pub mod encoding;
pub mod env;
pub mod folding;
pub mod read_proof;
pub mod storage;
pub mod storage_proof;
pub mod utils;

use mina_curves::pasta::{Fp, Fq, Pallas, PallasParameters, ProjectivePallas};
use mina_poseidon::{
    constants::PlonkSpongeConstantsKimchi,
    sponge::{DefaultFqSponge, DefaultFrSponge},
};

pub const SRS_SIZE: usize = 1 << 16;

pub type Curve = Pallas;
pub type ProjectiveCurve = ProjectivePallas;
pub type CurveParameters = PallasParameters;
pub type ScalarField = Fq;
pub type BaseField = Fp;

pub type CurveFqSponge = DefaultFqSponge<PallasParameters, PlonkSpongeConstantsKimchi>;
pub type CurveFrSponge = DefaultFrSponge<ScalarField, PlonkSpongeConstantsKimchi>;

//pub type ScalarSponge = DefaultFrSponge<Fp, SpongeParams>;
