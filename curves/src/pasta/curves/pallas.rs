use ark_ec::{
    models::CurveConfig,
    short_weierstrass::{self as sw, SWCurveConfig},
};
use ark_ff::{Field, MontFp, Zero};

use crate::pasta::{fp::Fp, fq::Fq};

#[derive(Debug, Copy, Clone, Default, PartialEq, Eq)]
pub struct Config;

impl CurveConfig for Config {
    type BaseField = Fp;
    type ScalarField = Fq;

    /// COFACTOR = 1
    const COFACTOR: &'static [u64] = &[0x1];

    /// COFACTOR_INV = 1
    const COFACTOR_INV: Self::ScalarField = Self::ScalarField::ONE;
}

pub type Affine = sw::Affine<Config>;
pub type Projective = sw::Projective<Config>;

impl SWCurveConfig for Config {
    /// COEFF_A = 0
    const COEFF_A: Self::BaseField = Self::BaseField::ZERO;

    /// COEFF_B = 5
    const COEFF_B: Self::BaseField = MontFp!("5");

    /// AFFINE_GENERATOR_COEFFS = (G1_GENERATOR_X, G1_GENERATOR_Y)
    const GENERATOR: Affine = Affine::new_unchecked(G_GENERATOR_X, G_GENERATOR_Y);

    #[inline(always)]
    fn mul_by_a(_: Self::BaseField) -> Self::BaseField {
        Self::BaseField::zero()
    }
}

/// G_GENERATOR_X =
/// 1
pub const G_GENERATOR_X: <Config as CurveConfig>::BaseField = MontFp!("1");

/// G1_GENERATOR_Y =
/// 12418654782883325593414442427049395787963493412651469444558597405572177144507
pub const G_GENERATOR_Y: <Config as CurveConfig>::BaseField =
    MontFp!("12418654782883325593414442427049395787963493412651469444558597405572177144507");

/// legacy curve, a copy of the normal curve to support legacy sponge params
#[derive(Copy, Clone, Default, PartialEq, Eq)]
pub struct LegacyConfig;

impl CurveConfig for LegacyConfig {
    type BaseField = <Config as CurveConfig>::BaseField;
    type ScalarField = <Config as CurveConfig>::ScalarField;
    const COFACTOR: &'static [u64] = <Config>::COFACTOR;
    const COFACTOR_INV: Self::ScalarField = <Config>::COFACTOR_INV;
}
impl SWCurveConfig for LegacyConfig {
    const COEFF_A: Self::BaseField = <Config as SWCurveConfig>::COEFF_A;
    const COEFF_B: Self::BaseField = <Config as SWCurveConfig>::COEFF_B;
    const GENERATOR: LegacyCurve = LegacyCurve::new_unchecked(G_GENERATOR_X, G_GENERATOR_Y);
}

pub type LegacyCurve = sw::Affine<LegacyConfig>;
