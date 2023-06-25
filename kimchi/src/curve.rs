//! This module contains a useful trait for recursion: [KimchiCurve],
//! which defines how a pair of curves interact.

use ark_ec::{short_weierstrass_jacobian::GroupAffine, AffineCurve, ModelParameters};
use mina_curves::pasta::curves::{
    pallas::{LegacyPallasParameters, PallasParameters},
    vesta::{LegacyVestaParameters, VestaParameters},
};
use mina_poseidon::poseidon::ArithmeticSpongeParams;
use once_cell::sync::Lazy;
use poly_commitment::{
    commitment::{CommitmentCurve, EndoCurve},
    srs::endos,
};

/// Represents additional information that a curve needs in order to be used with Kimchi
pub trait KimchiCurve: CommitmentCurve + EndoCurve {
    /// A human readable name.
    const NAME: &'static str;

    /// Provides the sponge params to be used with this curve.
    fn sponge_params() -> &'static ArithmeticSpongeParams<Self::ScalarField>;

    /// Provides the sponge params to be used with the other curve.
    fn other_curve_sponge_params() -> &'static ArithmeticSpongeParams<Self::BaseField>;

    /// Provides the coefficients for the curve endomorphism, called (q,r) in some places.
    fn endos() -> &'static (Self::BaseField, Self::ScalarField);

    /// Provides the coefficient for the curve endomorphism over the other field, called q in some
    /// places.
    fn other_curve_endo() -> &'static Self::ScalarField;

    /// Accessor for the other curve's prime subgroup generator, as coordinates
    // TODO: This leaked from snarky.rs. Stop the bleed.
    fn other_curve_prime_subgroup_generator() -> (Self::ScalarField, Self::ScalarField);
}

impl KimchiCurve for GroupAffine<VestaParameters> {
    const NAME: &'static str = "vesta";

    fn sponge_params() -> &'static ArithmeticSpongeParams<Self::ScalarField> {
        mina_poseidon::pasta::fp_kimchi::static_params()
    }

    fn other_curve_sponge_params() -> &'static ArithmeticSpongeParams<Self::BaseField> {
        mina_poseidon::pasta::fq_kimchi::static_params()
    }

    fn endos() -> &'static (Self::BaseField, Self::ScalarField) {
        static VESTA_ENDOS: Lazy<(
            <VestaParameters as ModelParameters>::BaseField,
            <VestaParameters as ModelParameters>::ScalarField,
        )> = Lazy::new(endos::<GroupAffine<VestaParameters>>);
        &VESTA_ENDOS
    }

    fn other_curve_endo() -> &'static Self::ScalarField {
        static PALLAS_ENDOS: Lazy<<PallasParameters as ModelParameters>::BaseField> =
            Lazy::new(|| endos::<GroupAffine<PallasParameters>>().0);
        &PALLAS_ENDOS
    }

    fn other_curve_prime_subgroup_generator() -> (Self::ScalarField, Self::ScalarField) {
        GroupAffine::<PallasParameters>::prime_subgroup_generator()
            .to_coordinates()
            .unwrap()
    }
}

impl KimchiCurve for GroupAffine<PallasParameters> {
    const NAME: &'static str = "pallas";

    fn sponge_params() -> &'static ArithmeticSpongeParams<Self::ScalarField> {
        mina_poseidon::pasta::fq_kimchi::static_params()
    }

    fn other_curve_sponge_params() -> &'static ArithmeticSpongeParams<Self::BaseField> {
        mina_poseidon::pasta::fp_kimchi::static_params()
    }

    fn endos() -> &'static (Self::BaseField, Self::ScalarField) {
        static PALLAS_ENDOS: Lazy<(
            <PallasParameters as ModelParameters>::BaseField,
            <PallasParameters as ModelParameters>::ScalarField,
        )> = Lazy::new(endos::<GroupAffine<PallasParameters>>);
        &PALLAS_ENDOS
    }

    fn other_curve_endo() -> &'static Self::ScalarField {
        static VESTA_ENDOS: Lazy<<VestaParameters as ModelParameters>::BaseField> =
            Lazy::new(|| endos::<GroupAffine<VestaParameters>>().0);
        &VESTA_ENDOS
    }

    fn other_curve_prime_subgroup_generator() -> (Self::ScalarField, Self::ScalarField) {
        GroupAffine::<VestaParameters>::prime_subgroup_generator()
            .to_coordinates()
            .unwrap()
    }
}

//
// Legacy curves
//

impl KimchiCurve for GroupAffine<LegacyVestaParameters> {
    const NAME: &'static str = "legacy_vesta";

    fn sponge_params() -> &'static ArithmeticSpongeParams<Self::ScalarField> {
        mina_poseidon::pasta::fp_legacy::static_params()
    }

    fn other_curve_sponge_params() -> &'static ArithmeticSpongeParams<Self::BaseField> {
        mina_poseidon::pasta::fq_legacy::static_params()
    }

    fn endos() -> &'static (Self::BaseField, Self::ScalarField) {
        GroupAffine::<VestaParameters>::endos()
    }

    fn other_curve_endo() -> &'static Self::ScalarField {
        static PALLAS_ENDOS: Lazy<<PallasParameters as ModelParameters>::BaseField> =
            Lazy::new(|| endos::<GroupAffine<PallasParameters>>().0);
        &PALLAS_ENDOS
    }

    fn other_curve_prime_subgroup_generator() -> (Self::ScalarField, Self::ScalarField) {
        GroupAffine::<PallasParameters>::prime_subgroup_generator()
            .to_coordinates()
            .unwrap()
    }
}

impl KimchiCurve for GroupAffine<LegacyPallasParameters> {
    const NAME: &'static str = "legacy_pallas";

    fn sponge_params() -> &'static ArithmeticSpongeParams<Self::ScalarField> {
        mina_poseidon::pasta::fq_legacy::static_params()
    }

    fn other_curve_sponge_params() -> &'static ArithmeticSpongeParams<Self::BaseField> {
        mina_poseidon::pasta::fp_legacy::static_params()
    }

    fn endos() -> &'static (Self::BaseField, Self::ScalarField) {
        GroupAffine::<PallasParameters>::endos()
    }

    fn other_curve_endo() -> &'static Self::ScalarField {
        static VESTA_ENDOS: Lazy<<VestaParameters as ModelParameters>::BaseField> =
            Lazy::new(|| endos::<GroupAffine<VestaParameters>>().0);
        &VESTA_ENDOS
    }

    fn other_curve_prime_subgroup_generator() -> (Self::ScalarField, Self::ScalarField) {
        GroupAffine::<VestaParameters>::prime_subgroup_generator()
            .to_coordinates()
            .unwrap()
    }
}
