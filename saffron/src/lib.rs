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

#[cfg(feature = "ocaml_types")]
pub use commitment::caml as caml_commitment;
#[cfg(feature = "ocaml_types")]
pub use diff::caml as caml_diff;
#[cfg(feature = "ocaml_types")]
pub use storage::caml as caml_storage;

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
