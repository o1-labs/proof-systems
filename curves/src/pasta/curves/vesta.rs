use crate::pasta::*;
use ark_ec::{
    models::short_weierstrass_jacobian::{GroupAffine, GroupProjective},
    ModelParameters, SWModelParameters,
};
use ark_ff::{field_new, Zero};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VestaParameters;

impl ModelParameters for VestaParameters {
    type BaseField = Fq;
    type ScalarField = Fp;
}

pub type Vesta = GroupAffine<VestaParameters>;
pub type Projective = GroupProjective<VestaParameters>;

impl SWModelParameters for VestaParameters {
    /// COEFF_A = 0
    const COEFF_A: Fq = field_new!(Fq, "0");

    /// COEFF_B = 5
    const COEFF_B: Fq = field_new!(Fq, "5");

    /// COFACTOR = 1
    const COFACTOR: &'static [u64] = &[0x1];

    /// COFACTOR_INV = 1
    const COFACTOR_INV: Fp = field_new!(Fp, "1");

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
pub const G_GENERATOR_X: Fq = field_new!(Fq, "1");

/// G1_GENERATOR_Y =
/// 11426906929455361843568202299992114520848200991084027513389447476559454104162
pub const G_GENERATOR_Y: Fq = field_new!(
    Fq,
    "11426906929455361843568202299992114520848200991084027513389447476559454104162"
);

/// legacy curve, a copy of the normal curve to support legacy sponge params
#[derive(Copy, Clone, Default, PartialEq, Eq)]
pub struct LegacyVestaParameters;

impl ModelParameters for LegacyVestaParameters {
    type BaseField = <VestaParameters as ModelParameters>::BaseField;
    type ScalarField = <VestaParameters as ModelParameters>::ScalarField;
}
impl SWModelParameters for LegacyVestaParameters {
    const COEFF_A: Self::BaseField = <VestaParameters as SWModelParameters>::COEFF_A;
    const COEFF_B: Self::BaseField = <VestaParameters as SWModelParameters>::COEFF_B;
    const COFACTOR: &'static [u64] = <VestaParameters as SWModelParameters>::COFACTOR;
    const COFACTOR_INV: Self::ScalarField = <VestaParameters as SWModelParameters>::COFACTOR_INV;
    const AFFINE_GENERATOR_COEFFS: (Self::BaseField, Self::BaseField) =
        <VestaParameters as SWModelParameters>::AFFINE_GENERATOR_COEFFS;
}

pub type LegacyVesta = GroupAffine<LegacyVestaParameters>;
