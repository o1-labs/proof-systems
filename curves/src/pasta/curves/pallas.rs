use ark_ec::{
    models::CurveConfig,
    short_weierstrass::{self as sw, SWCurveConfig},
};
use ark_ff::{Field, MontFp, Zero};

use crate::pasta::{fp::Fp, fq::Fq};

#[derive(Debug, Copy, Clone, Default, PartialEq, Eq)]
pub struct PallasConfig;

impl CurveConfig for PallasConfig {
    type BaseField = Fp;
    type ScalarField = Fq;

    /// COFACTOR = 1
    const COFACTOR: &'static [u64] = &[0x1];

    /// COFACTOR_INV = 1
    const COFACTOR_INV: Fq = Fq::ONE;
}

pub type Affine = sw::Affine<PallasConfig>;
pub type Projective = sw::Projective<PallasConfig>;

impl SWCurveConfig for PallasConfig {
    /// COEFF_A = 0
    const COEFF_A: Fp = Fp::ZERO;

    /// COEFF_B = 5
    const COEFF_B: Fp = MontFp!("5");

    /// AFFINE_GENERATOR_COEFFS = (G1_GENERATOR_X, G1_GENERATOR_Y)
    const GENERATOR: Affine = Affine::new_unchecked(G_GENERATOR_X, G_GENERATOR_Y);

    #[inline(always)]
    fn mul_by_a(_: Self::BaseField) -> Self::BaseField {
        Self::BaseField::zero()
    }
}

/// G_GENERATOR_X =
/// 1
pub const G_GENERATOR_X: Fp = MontFp!("1");

/// G1_GENERATOR_Y =
/// 12418654782883325593414442427049395787963493412651469444558597405572177144507
pub const G_GENERATOR_Y: Fp =
    MontFp!("12418654782883325593414442427049395787963493412651469444558597405572177144507");

/// legacy curve, a copy of the normal curve to support legacy sponge params
#[derive(Copy, Clone, Default, PartialEq, Eq)]
pub struct LegacyPallasConfig;

impl CurveConfig for LegacyPallasConfig {
    type BaseField = <PallasConfig as CurveConfig>::BaseField;
    type ScalarField = <PallasConfig as CurveConfig>::ScalarField;
    const COFACTOR: &'static [u64] = <PallasConfig>::COFACTOR;
    const COFACTOR_INV: Self::ScalarField = <PallasConfig>::COFACTOR_INV;
}
impl SWCurveConfig for LegacyPallasConfig {
    const COEFF_A: Self::BaseField = <PallasConfig as SWCurveConfig>::COEFF_A;
    const COEFF_B: Self::BaseField = <PallasConfig as SWCurveConfig>::COEFF_B;
    const GENERATOR: LegacyPallas = LegacyPallas::new_unchecked(G_GENERATOR_X, G_GENERATOR_Y);
}

pub type LegacyPallas = sw::Affine<LegacyPallasConfig>;
