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
use kimchi_stubs::field_vector;
#[cfg(feature = "ocaml_types")]
pub use read_proof::caml as caml_read_proof;
#[cfg(feature = "ocaml_types")]
pub use storage::caml as caml_storage;

use mina_poseidon::{
    constants::PlonkSpongeConstantsKimchi,
    sponge::{DefaultFqSponge, DefaultFrSponge},
};

pub const SRS_SIZE: usize = 1 << 16;

pub type Curve = mina_curves::pasta::Pallas;
pub type ProjectiveCurve = mina_curves::pasta::ProjectivePallas;
pub type CurveParameters = mina_curves::pasta::PallasParameters;
pub type ScalarField = <CurveParameters as ark_ec::CurveConfig>::ScalarField;
pub type BaseField = <CurveParameters as ark_ec::CurveConfig>::BaseField;

pub type CurveFqSponge = DefaultFqSponge<CurveParameters, PlonkSpongeConstantsKimchi>;
pub type CurveFrSponge = DefaultFrSponge<ScalarField, PlonkSpongeConstantsKimchi>;

#[cfg(feature = "ocaml_types")]
pub type CamlG = kimchi_stubs::arkworks::CamlGPallas;
#[cfg(feature = "ocaml_types")]
pub type CamlScalar = kimchi_stubs::arkworks::CamlFq;
#[cfg(feature = "ocaml_types")]
pub type CamlSrs = kimchi_stubs::srs::fq::CamlFqSrs;
#[cfg(feature = "ocaml_types")]
pub type CamlScalarVector = field_vector::fq::CamlFqVector;
