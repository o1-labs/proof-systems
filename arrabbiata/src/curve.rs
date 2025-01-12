//! This file defines a trait similar to [kimchi::curve::KimchiCurve] for Pallas and
//! Vesta. It aims to define all the parameters that are needed by a curve to be
//! used in Arrabbiata. For instance, the sponge parameters, the endomorphism
//! coefficients, etc.
//! The goal of this trait is to parametrize the whole library with the
//! different curves.

use ark_ec::short_weierstrass::Affine;
use ark_ff::PrimeField;
use kimchi::curve::{pallas_endos, vesta_endos};
use mina_curves::pasta::curves::{pallas::PallasParameters, vesta::VestaParameters};
use mina_poseidon::{constants::SpongeConstants, poseidon::ArithmeticSpongeParams};
use poly_commitment::commitment::{CommitmentCurve, EndoCurve};

#[derive(Clone)]
pub struct PlonkSpongeConstants {}

impl SpongeConstants for PlonkSpongeConstants {
    const SPONGE_CAPACITY: usize = 1;
    const SPONGE_WIDTH: usize = 3;
    const SPONGE_RATE: usize = 2;
    const PERM_ROUNDS_FULL: usize = 60;
    const PERM_ROUNDS_PARTIAL: usize = 0;
    const PERM_HALF_ROUNDS_FULL: usize = 0;
    const PERM_SBOX: u32 = 5;
    const PERM_FULL_MDS: bool = true;
    const PERM_INITIAL_ARK: bool = false;
}

/// Represents additional information that a curve needs in order to be used
/// with Arrabbiata.
pub trait ArrabbiataCurve: CommitmentCurve + EndoCurve
where
    Self::BaseField: PrimeField,
{
    /// A human readable name.
    const NAME: &'static str;

    // FIXME: use this in the codebase.
    // We might want to use different sponge constants for different curves.
    // For now, it does use the same constants for both curves.
    type SpongeConstants: SpongeConstants;

    const SPONGE_CONSTANTS: Self::SpongeConstants;

    /// Provides the sponge params to be used with this curve.
    fn sponge_params() -> &'static ArithmeticSpongeParams<Self::ScalarField>;

    /// Provides the sponge params to be used with the other curve.
    fn other_curve_sponge_params() -> &'static ArithmeticSpongeParams<Self::BaseField>;

    /// Provides the coefficients for the curve endomorphism, called (q,r) in
    /// some places.
    fn endos() -> &'static (Self::BaseField, Self::ScalarField);

    /// Provides the coefficient for the curve endomorphism over the other
    /// field, called q in some places.
    fn other_curve_endo() -> &'static Self::ScalarField;
}

impl ArrabbiataCurve for Affine<PallasParameters> {
    const NAME: &'static str = "pallas";

    type SpongeConstants = PlonkSpongeConstants;

    const SPONGE_CONSTANTS: Self::SpongeConstants = PlonkSpongeConstants {};

    fn sponge_params() -> &'static ArithmeticSpongeParams<Self::ScalarField> {
        crate::poseidon_3_60_0_5_5_fq::static_params()
    }

    fn other_curve_sponge_params() -> &'static ArithmeticSpongeParams<Self::BaseField> {
        crate::poseidon_3_60_0_5_5_fp::static_params()
    }

    fn endos() -> &'static (Self::BaseField, Self::ScalarField) {
        pallas_endos()
    }

    fn other_curve_endo() -> &'static Self::ScalarField {
        &vesta_endos().0
    }
}

impl ArrabbiataCurve for Affine<VestaParameters> {
    const NAME: &'static str = "vesta";

    type SpongeConstants = PlonkSpongeConstants;

    const SPONGE_CONSTANTS: Self::SpongeConstants = PlonkSpongeConstants {};

    fn sponge_params() -> &'static ArithmeticSpongeParams<Self::ScalarField> {
        crate::poseidon_3_60_0_5_5_fp::static_params()
    }

    fn other_curve_sponge_params() -> &'static ArithmeticSpongeParams<Self::BaseField> {
        crate::poseidon_3_60_0_5_5_fq::static_params()
    }

    fn endos() -> &'static (Self::BaseField, Self::ScalarField) {
        vesta_endos()
    }

    fn other_curve_endo() -> &'static Self::ScalarField {
        &pallas_endos().0
    }
}
