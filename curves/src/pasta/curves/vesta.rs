use ark_ec::{
    models::CurveConfig,
    short_weierstrass::{self as sw, SWCurveConfig},
};
use ark_ff::{Field, MontFp, Zero};

use crate::pasta::{fp::Fp, fq::Fq};

#[derive(Debug, Copy, Clone, Default, PartialEq, Eq)]
pub struct VestaConfig;

impl CurveConfig for VestaConfig {
    type BaseField = Fq;
    type ScalarField = Fp;

    /// COFACTOR = 1
    const COFACTOR: &'static [u64] = &[0x1];

    /// COFACTOR_INV = 1
    const COFACTOR_INV: Fp = Fp::ONE;
}

pub type Affine = sw::Affine<VestaConfig>;
pub type Projective = sw::Projective<VestaConfig>;

impl SWCurveConfig for VestaConfig {
    /// COEFF_A = 0
    const COEFF_A: Fq = Fq::ZERO;

    /// COEFF_B = 5
    const COEFF_B: Fq = MontFp!("5");

    /// AFFINE_GENERATOR_COEFFS = (G1_GENERATOR_X, G1_GENERATOR_Y)
    const GENERATOR: Affine = Affine::new_unchecked(G_GENERATOR_X, G_GENERATOR_Y);

    #[inline(always)]
    fn mul_by_a(_: Self::BaseField) -> Self::BaseField {
        Self::BaseField::zero()
    }
}

/// G_GENERATOR_X =
/// 1
pub const G_GENERATOR_X: Fq = MontFp!("1");

/// G1_GENERATOR_Y =
/// 11426906929455361843568202299992114520848200991084027513389447476559454104162
pub const G_GENERATOR_Y: Fq =
    MontFp!("11426906929455361843568202299992114520848200991084027513389447476559454104162");

/// legacy curve, a copy of the normal curve to support legacy sponge params
#[derive(Copy, Clone, Default, PartialEq, Eq)]
pub struct LegacyVestaConfig;

impl CurveConfig for LegacyVestaConfig {
    type BaseField = <VestaConfig as CurveConfig>::BaseField;
    type ScalarField = <VestaConfig as CurveConfig>::ScalarField;
    const COFACTOR: &'static [u64] = <VestaConfig>::COFACTOR;
    const COFACTOR_INV: Self::ScalarField = <VestaConfig>::COFACTOR_INV;
}
impl SWCurveConfig for LegacyVestaConfig {
    const COEFF_A: Self::BaseField = <VestaConfig as SWCurveConfig>::COEFF_A;
    const COEFF_B: Self::BaseField = <VestaConfig as SWCurveConfig>::COEFF_B;
    const GENERATOR: LegacyVesta = LegacyVesta::new_unchecked(G_GENERATOR_X, G_GENERATOR_Y);
}

pub type LegacyVesta = sw::Affine<LegacyVestaConfig>;
