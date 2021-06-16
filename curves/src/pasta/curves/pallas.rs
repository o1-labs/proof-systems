use crate::pasta::*;
use ark_ec::{
    models::short_weierstrass_jacobian::{GroupAffine, GroupProjective},
    ModelParameters, SWModelParameters,
};
use ark_ff::{biginteger::BigInteger256, field_new, Zero};

#[derive(Copy, Clone, Default, PartialEq, Eq)]
pub struct PallasParameters;

impl ModelParameters for PallasParameters {
    type BaseField = Fp;
    type ScalarField = Fq;
}

pub type Affine = GroupAffine<PallasParameters>;
pub type Projective = GroupProjective<PallasParameters>;

impl SWModelParameters for PallasParameters {
    /// COEFF_A = 0
    const COEFF_A: Fp = field_new!(Fp, "0");

    /// COEFF_B = 5
    const COEFF_B: Fp = field_new!(Fp, "5");

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
/// 12418654782883325593414442427049395787963493412651469444558597405572177144507
pub const G_GENERATOR_Y: Fp = field_new!(
    Fp,
    "12418654782883325593414442427049395787963493412651469444558597405572177144507"
);
