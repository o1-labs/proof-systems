use crate::{
    biginteger::BigInteger256,
    curves::{
        models::short_weierstrass_jacobian::{GroupAffine, GroupProjective},
        ModelParameters, SWModelParameters},
    field_new, Zero,
    pasta::*
};

#[derive(Copy, Clone, Default, PartialEq, Eq)]
pub struct VestaParameters;

impl ModelParameters for VestaParameters {
    type BaseField = Fq;
    type ScalarField = Fp;
}

pub type Affine = GroupAffine<VestaParameters>;
pub type Projective = GroupProjective<VestaParameters>;

impl SWModelParameters for VestaParameters {
    /// COEFF_A = 0
    const COEFF_A: Fq = field_new!(Fq, BigInteger256([0x0, 0x0, 0x0, 0x0]));

    /// COEFF_B = 5
    const COEFF_B: Fq = field_new!(
        Fq,
        BigInteger256([
            0x96bc8c8cffffffed, 0x74c2a54b49f7778e, 0xfffffffffffffffd, 0x3fffffffffffffff
        ])
    );

    /// COFACTOR = 1
    const COFACTOR: &'static [u64] = &[0x1];

    /// COFACTOR_INV = 1
    const COFACTOR_INV: Fp = field_new!(
        Fp,
        BigInteger256([
            0x34786d38fffffffd, 0x992c350be41914ad, 0xffffffffffffffff, 0x3fffffffffffffff
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
pub const G_GENERATOR_X: Fq = field_new!(
    Fq,
    BigInteger256([
        0x5b2b3e9cfffffffd, 0x992c350be3420567, 0xffffffffffffffff, 0x3fffffffffffffff
    ])
);

/// G1_GENERATOR_Y =
/// 11426906929455361843568202299992114520848200991084027513389447476559454104162
pub const G_GENERATOR_Y: Fq = field_new!(
    Fq,
    BigInteger256([
        0x9aae9ab8f909fe12, 0x4ef425ddfec978ab, 0x80532e1caba65bb9, 0x1104486c25ae2958
    ])
);
