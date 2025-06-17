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

use mina_poseidon::{
    constants::PlonkSpongeConstantsKimchi,
    sponge::{DefaultFqSponge, DefaultFrSponge},
};

pub const SRS_SIZE: usize = 1 << 16;

pub type Curve = mina_curves::pasta::Vesta;
pub type ProjectiveCurve = mina_curves::pasta::ProjectiveVesta;
pub type CurveParameters = mina_curves::pasta::VestaParameters;
pub type ScalarField = <CurveParameters as ark_ec::CurveConfig>::ScalarField;
pub type BaseField = <CurveParameters as ark_ec::CurveConfig>::BaseField;

pub type CurveFqSponge = DefaultFqSponge<CurveParameters, PlonkSpongeConstantsKimchi>;
pub type CurveFrSponge = DefaultFrSponge<ScalarField, PlonkSpongeConstantsKimchi>;
