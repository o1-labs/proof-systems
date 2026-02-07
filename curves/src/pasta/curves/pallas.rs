use crate::pasta::{Fp, Fq};
use ark_ec::{
    models::short_weierstrass::{Affine, Projective, SWCurveConfig},
    CurveConfig,
};
use ark_ff::{MontFp, Zero};

/// `G_GENERATOR_X` =
/// 1
pub const G_GENERATOR_X: Fp = MontFp!("1");

/// `G1_GENERATOR_Y` =
/// 12418654782883325593414442427049395787963493412651469444558597405572177144507
pub const G_GENERATOR_Y: Fp =
    MontFp!("12418654782883325593414442427049395787963493412651469444558597405572177144507");

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PallasParameters;

impl CurveConfig for PallasParameters {
    type BaseField = Fp;

    type ScalarField = Fq;

    /// COFACTOR = 1
    const COFACTOR: &'static [u64] = &[0x1];

    /// `COFACTOR_INV` = 1
    const COFACTOR_INV: Fq = MontFp!("1");
}

pub type Pallas = Affine<PallasParameters>;

pub type ProjectivePallas = Projective<PallasParameters>;

impl SWCurveConfig for PallasParameters {
    const COEFF_A: Self::BaseField = MontFp!("0");

    const COEFF_B: Self::BaseField = MontFp!("5");

    const GENERATOR: Affine<Self> = Affine::new_unchecked(G_GENERATOR_X, G_GENERATOR_Y);
}

impl PallasParameters {
    #[inline]
    #[must_use]
    pub fn mul_by_a(_: &<Self as CurveConfig>::BaseField) -> <Self as CurveConfig>::BaseField {
        <Self as CurveConfig>::BaseField::zero()
    }
}

/// legacy curve, a copy of the normal curve to support legacy sponge params
#[derive(Copy, Clone, Default, PartialEq, Eq)]
pub struct LegacyPallasParameters;

impl CurveConfig for LegacyPallasParameters {
    type BaseField = <PallasParameters as CurveConfig>::BaseField;

    type ScalarField = <PallasParameters as CurveConfig>::ScalarField;

    const COFACTOR: &'static [u64] = <PallasParameters as CurveConfig>::COFACTOR;

    const COFACTOR_INV: Self::ScalarField = <PallasParameters as CurveConfig>::COFACTOR_INV;
}

impl SWCurveConfig for LegacyPallasParameters {
    const COEFF_A: Self::BaseField = <PallasParameters as SWCurveConfig>::COEFF_A;

    const COEFF_B: Self::BaseField = <PallasParameters as SWCurveConfig>::COEFF_B;

    const GENERATOR: Affine<Self> = Affine::new_unchecked(G_GENERATOR_X, G_GENERATOR_Y);
}

pub type LegacyPallas = Affine<LegacyPallasParameters>;
