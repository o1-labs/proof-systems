use crate::pasta::*;
use algebra::{
    biginteger::BigInteger256,
    curves::{
        models::short_weierstrass_jacobian::{GroupAffine, GroupProjective},
        ModelParameters, SWModelParameters,
    },
    field_new, Zero,
};

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
    const COEFF_A: Fp = field_new!(Fp, BigInteger256([0x0, 0x0, 0x0, 0x0]));

    /// COEFF_B = 5
    const COEFF_B: Fp = field_new!(
        Fp,
        BigInteger256([
            0xa1a55e68ffffffed,
            0x74c2a54b4f4982f3,
            0xfffffffffffffffd,
            0x3fffffffffffffff
        ])
    );

    /// COFACTOR = 1
    const COFACTOR: &'static [u64] = &[0x1];

    /// COFACTOR_INV = 1
    const COFACTOR_INV: Fq = field_new!(
        Fq,
        BigInteger256([
            0x5b2b3e9cfffffffd,
            0x992c350be3420567,
            0xffffffffffffffff,
            0x3fffffffffffffff
        ])
    );

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
pub const G_GENERATOR_X: Fp = field_new!(
    Fp,
    BigInteger256([
        0x34786d38fffffffd,
        0x992c350be41914ad,
        0xffffffffffffffff,
        0x3fffffffffffffff
    ])
);

/// G1_GENERATOR_Y =
/// 12418654782883325593414442427049395787963493412651469444558597405572177144507
pub const G_GENERATOR_Y: Fp = field_new!(
    Fp,
    BigInteger256([
        0x2f474795455d409d,
        0xb443b9b74b8255d9,
        0x270c412f2c9a5d66,
        0x8e00f71ba43dd6b
    ])
);
