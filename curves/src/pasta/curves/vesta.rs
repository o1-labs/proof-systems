use crate::pasta::{Fp, Fq};
use ark_ec::{
    models::short_weierstrass::{Affine, Projective, SWCurveConfig},
    CurveConfig,
};
use ark_ff::{MontFp, Zero};

/// `G_GENERATOR_X` =
/// 1
pub const G_GENERATOR_X: Fq = MontFp!("1");

/// `G1_GENERATOR_Y` =
/// 11426906929455361843568202299992114520848200991084027513389447476559454104162
pub const G_GENERATOR_Y: Fq =
    MontFp!("11426906929455361843568202299992114520848200991084027513389447476559454104162");

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VestaParameters;

impl CurveConfig for VestaParameters {
    type BaseField = Fq;
    type ScalarField = Fp;

    /// COFACTOR = 1
    const COFACTOR: &'static [u64] = &[0x1];

    /// `COFACTOR_INV` = 1
    const COFACTOR_INV: Fp = MontFp!("1");
}

pub type Vesta = Affine<VestaParameters>;
pub type ProjectiveVesta = Projective<VestaParameters>;

impl SWCurveConfig for VestaParameters {
    /// `COEFF_A` = 0
    const COEFF_A: Fq = MontFp!("0");

    /// `COEFF_B` = 5
    const COEFF_B: Fq = MontFp!("5");

    /// `AFFINE_GENERATOR_COEFFS` = (`G1_GENERATOR_X`, `G1_GENERATOR_Y`)
    const GENERATOR: Affine<Self> = Affine::new_unchecked(G_GENERATOR_X, G_GENERATOR_Y);
}

impl VestaParameters {
    #[inline]
    #[must_use]
    pub fn mul_by_a(_: &<Self as CurveConfig>::BaseField) -> <Self as CurveConfig>::BaseField {
        <Self as CurveConfig>::BaseField::zero()
    }
}

/// legacy curve, a copy of the normal curve to support legacy sponge params
#[derive(Copy, Clone, Default, PartialEq, Eq)]
pub struct LegacyVestaParameters;

impl CurveConfig for LegacyVestaParameters {
    type BaseField = <VestaParameters as CurveConfig>::BaseField;
    type ScalarField = <VestaParameters as CurveConfig>::ScalarField;
    const COFACTOR: &'static [u64] = <VestaParameters as CurveConfig>::COFACTOR;
    const COFACTOR_INV: Self::ScalarField = <VestaParameters as CurveConfig>::COFACTOR_INV;
}

impl SWCurveConfig for LegacyVestaParameters {
    const COEFF_A: Self::BaseField = <VestaParameters as SWCurveConfig>::COEFF_A;
    const COEFF_B: Self::BaseField = <VestaParameters as SWCurveConfig>::COEFF_B;
    const GENERATOR: Affine<Self> = Affine::new_unchecked(G_GENERATOR_X, G_GENERATOR_Y);
}

pub type LegacyVesta = Affine<LegacyVestaParameters>;
