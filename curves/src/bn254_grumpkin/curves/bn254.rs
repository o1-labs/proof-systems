//! Implementation of BN254
//! Copy from <https://github.com/arkworks-rs/curves/blob/v0.3.0/bn254/src/curves/g1.rs>

use crate::bn254_grumpkin::fields::{fp::Fp, fq::Fq};
use ark_ec::{
    models::short_weierstrass_jacobian::{GroupAffine, GroupProjective},
    ModelParameters, SWModelParameters,
};
use ark_ff::{field_new, Zero};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BN254Parameters;

impl ModelParameters for BN254Parameters {
    type BaseField = Fq;
    type ScalarField = Fp;
}

pub type BN254 = GroupAffine<BN254Parameters>;
pub type ProjectiveBN254 = GroupProjective<BN254Parameters>;

impl SWModelParameters for BN254Parameters {
    /// COEFF_A = 0
    const COEFF_A: Fq = field_new!(Fq, "0");

    /// COEFF_B = 3
    const COEFF_B: Fq = field_new!(Fq, "3");

    /// COFACTOR = 1
    const COFACTOR: &'static [u64] = &[0x1];

    /// COFACTOR_INV = COFACTOR^{-1} mod r = 1
    const COFACTOR_INV: Fp = field_new!(Fp, "1");

    /// AFFINE_GENERATOR_COEFFS = (G1_GENERATOR_X, G1_GENERATOR_Y)
    const AFFINE_GENERATOR_COEFFS: (Self::BaseField, Self::BaseField) =
        (G_GENERATOR_X, G_GENERATOR_Y);

    #[inline(always)]
    fn mul_by_a(_: &Self::BaseField) -> Self::BaseField {
        Self::BaseField::zero()
    }
}

/// G1_GENERATOR_X = 1
pub const G_GENERATOR_X: Fq = field_new!(Fq, "1");

/// G1_GENERATOR_Y = 2
pub const G_GENERATOR_Y: Fq = field_new!(Fq, "2");
