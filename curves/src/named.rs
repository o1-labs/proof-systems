use crate::pasta::curves::{
    pallas::{LegacyPallasParameters, PallasParameters},
    vesta::{LegacyVestaParameters, VestaParameters},
};
use ark_ec::short_weierstrass::Affine;

/// Represents a curve that has a static name attached to it.
pub trait NamedCurve {
    /// A human readable name.
    const NAME: &'static str;
}

impl NamedCurve for Affine<VestaParameters> {
    const NAME: &'static str = "vesta";
}

impl NamedCurve for Affine<PallasParameters> {
    const NAME: &'static str = "pallas";
}

impl NamedCurve for Affine<LegacyVestaParameters> {
    const NAME: &'static str = "legacy_vesta";
}

impl NamedCurve for Affine<LegacyPallasParameters> {
    const NAME: &'static str = "legacy_pallas";
}

impl NamedCurve for Affine<ark_bn254::g1::Config> {
    const NAME: &'static str = "bn254";
}

impl NamedCurve for Affine<ark_secp256k1::Config> {
    const NAME: &'static str = "secp256k1";
}
