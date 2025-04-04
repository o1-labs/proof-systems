pub mod blob;
pub mod cli;
pub mod commitment;
pub mod diff;
pub mod env;
pub mod storage_proof;
pub mod utils;

use mina_curves::pasta::{Fp, Fq, ProjectiveVesta, Vesta, VestaParameters};
use mina_poseidon::{
    constants::PlonkSpongeConstantsKimchi,
    sponge::{DefaultFqSponge, DefaultFrSponge},
};

pub const SRS_SIZE: usize = 1 << 16;

pub type Curve = Vesta;
pub type ProjectiveCurve = ProjectiveVesta;
pub type CurveParameters = VestaParameters;
pub type ScalarField = Fp;
pub type BaseField = Fq;

pub type CurveFqSponge = DefaultFqSponge<VestaParameters, PlonkSpongeConstantsKimchi>;
pub type CurveFrSponge = DefaultFrSponge<ScalarField, PlonkSpongeConstantsKimchi>;

//pub type ScalarSponge = DefaultFrSponge<Fp, SpongeParams>;
