//! Grumpkin
//! Copy from <https://github.com/arkworks-rs/curves/blob/8c0256ac9c479b4b3beb91bfcc11dc17e58b3819/grumpkin/src/curves/mod.rs>

use crate::bn254_grumpkin::fields::{fp::Fp, fq::Fq};
use ark_ec::{
    models::short_weierstrass_jacobian::{GroupAffine, GroupProjective},
    ModelParameters, SWModelParameters,
};
use ark_ff::{field_new, Zero};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GrumpkinParameters;

impl ModelParameters for GrumpkinParameters {
    type BaseField = Fp;
    type ScalarField = Fq;
}

pub type Grumpkin = GroupAffine<GrumpkinParameters>;
pub type ProjectiveGrumpkin = GroupProjective<GrumpkinParameters>;

impl SWModelParameters for GrumpkinParameters {
    /// COEFF_A = 0
    const COEFF_A: Fp = field_new!(Fp, "0");

    /// COEFF_B = 5
    const COEFF_B: Fp = field_new!(Fp, "-17");

    /// COFACTOR = 1
    const COFACTOR: &'static [u64] = &[0x1];

    /// COFACTOR_INV = 1
    const COFACTOR_INV: Fq = field_new!(Fq, "1");

    /// AFFINE_GENERATOR_COEFFS = (G1_GENERATOR_X, G1_GENERATOR_Y)
    const AFFINE_GENERATOR_COEFFS: (Self::BaseField, Self::BaseField) =
        (G_GENERATOR_X, G_GENERATOR_Y);

    #[inline(always)]
    fn mul_by_a(_: &Self::BaseField) -> Self::BaseField {
        Self::BaseField::zero()
    }
}

/// G_GENERATOR_X =
/// 1
pub const G_GENERATOR_X: Fp = field_new!(Fp, "1");

/// G1_GENERATOR_Y =
/// 17631683881184975370165255887551781615748388533673675138860
pub const G_GENERATOR_Y: Fp = field_new!(
    Fp,
    "17631683881184975370165255887551781615748388533673675138860"
);
