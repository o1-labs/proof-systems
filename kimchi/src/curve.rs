//! This module contains a useful trait for recursion: [KimchiCurve],
//! which defines how a pair of curves interact.

use ark_ec::{short_weierstrass::Affine, AffineRepr, CurveConfig};
use mina_curves::{
    named::NamedCurve,
    pasta::curves::{
        pallas::{LegacyPallasParameters, PallasParameters, WasmPallasParameters},
        vesta::{LegacyVestaParameters, VestaParameters},
    },
};
use mina_poseidon::poseidon::ArithmeticSpongeParams;
use once_cell::sync::Lazy;
use poly_commitment::{
    commitment::{CommitmentCurve, EndoCurve},
    ipa::endos,
};

/// Represents additional information that a curve needs in order to be used
/// with Kimchi
pub trait KimchiCurve: CommitmentCurve + EndoCurve + NamedCurve {
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

    /// Accessor for the other curve's prime subgroup generator, as coordinates
    // TODO: This leaked from snarky.rs. Stop the bleed.
    fn other_curve_generator() -> (Self::ScalarField, Self::ScalarField);
}

pub fn vesta_endos() -> &'static (
    <VestaParameters as CurveConfig>::BaseField,
    <VestaParameters as CurveConfig>::ScalarField,
) {
    static VESTA_ENDOS: Lazy<(
        <VestaParameters as CurveConfig>::BaseField,
        <VestaParameters as CurveConfig>::ScalarField,
    )> = Lazy::new(endos::<Affine<VestaParameters>>);
    &VESTA_ENDOS
}

pub fn pallas_endos() -> &'static (
    <PallasParameters as CurveConfig>::BaseField,
    <PallasParameters as CurveConfig>::ScalarField,
) {
    static PALLAS_ENDOS: Lazy<(
        <PallasParameters as CurveConfig>::BaseField,
        <PallasParameters as CurveConfig>::ScalarField,
    )> = Lazy::new(endos::<Affine<PallasParameters>>);
    &PALLAS_ENDOS
}

impl KimchiCurve for Affine<VestaParameters> {
    fn sponge_params() -> &'static ArithmeticSpongeParams<Self::ScalarField> {
        mina_poseidon::pasta::fp_kimchi::static_params()
    }

    fn other_curve_sponge_params() -> &'static ArithmeticSpongeParams<Self::BaseField> {
        mina_poseidon::pasta::fq_kimchi::static_params()
    }

    fn endos() -> &'static (Self::BaseField, Self::ScalarField) {
        vesta_endos()
    }

    fn other_curve_endo() -> &'static Self::ScalarField {
        &pallas_endos().0
    }

    fn other_curve_generator() -> (Self::ScalarField, Self::ScalarField) {
        Affine::<PallasParameters>::generator()
            .to_coordinates()
            .unwrap()
    }
}

impl KimchiCurve for Affine<PallasParameters> {
    fn sponge_params() -> &'static ArithmeticSpongeParams<Self::ScalarField> {
        mina_poseidon::pasta::fq_kimchi::static_params()
    }

    fn other_curve_sponge_params() -> &'static ArithmeticSpongeParams<Self::BaseField> {
        mina_poseidon::pasta::fp_kimchi::static_params()
    }

    fn endos() -> &'static (Self::BaseField, Self::ScalarField) {
        pallas_endos()
    }

    fn other_curve_endo() -> &'static Self::ScalarField {
        &vesta_endos().0
    }

    fn other_curve_generator() -> (Self::ScalarField, Self::ScalarField) {
        Affine::<VestaParameters>::generator()
            .to_coordinates()
            .unwrap()
    }
}

//
// Legacy curves
//

impl KimchiCurve for Affine<LegacyVestaParameters> {
    fn sponge_params() -> &'static ArithmeticSpongeParams<Self::ScalarField> {
        mina_poseidon::pasta::fp_legacy::static_params()
    }

    fn other_curve_sponge_params() -> &'static ArithmeticSpongeParams<Self::BaseField> {
        mina_poseidon::pasta::fq_legacy::static_params()
    }

    fn endos() -> &'static (Self::BaseField, Self::ScalarField) {
        vesta_endos()
    }

    fn other_curve_endo() -> &'static Self::ScalarField {
        &pallas_endos().0
    }

    fn other_curve_generator() -> (Self::ScalarField, Self::ScalarField) {
        Affine::<PallasParameters>::generator()
            .to_coordinates()
            .unwrap()
    }
}

impl KimchiCurve for Affine<LegacyPallasParameters> {
    fn sponge_params() -> &'static ArithmeticSpongeParams<Self::ScalarField> {
        mina_poseidon::pasta::fq_legacy::static_params()
    }

    fn other_curve_sponge_params() -> &'static ArithmeticSpongeParams<Self::BaseField> {
        mina_poseidon::pasta::fp_legacy::static_params()
    }

    fn endos() -> &'static (Self::BaseField, Self::ScalarField) {
        pallas_endos()
    }

    fn other_curve_endo() -> &'static Self::ScalarField {
        &vesta_endos().0
    }

    fn other_curve_generator() -> (Self::ScalarField, Self::ScalarField) {
        Affine::<VestaParameters>::generator()
            .to_coordinates()
            .unwrap()
    }
}

#[cfg(feature = "bn254")]
use mina_poseidon::dummy_values::kimchi_dummy;

#[cfg(feature = "bn254")]
impl KimchiCurve for Affine<ark_bn254::g1::Config> {
    fn sponge_params() -> &'static ArithmeticSpongeParams<Self::ScalarField> {
        // TODO: Generate some params
        static PARAMS: Lazy<ArithmeticSpongeParams<ark_bn254::Fr>> = Lazy::new(kimchi_dummy);
        &PARAMS
    }

    fn other_curve_sponge_params() -> &'static ArithmeticSpongeParams<Self::BaseField> {
        // TODO: Generate some params
        static PARAMS: Lazy<ArithmeticSpongeParams<ark_bn254::Fq>> = Lazy::new(kimchi_dummy);
        &PARAMS
    }

    fn endos() -> &'static (Self::BaseField, Self::ScalarField) {
        static ENDOS: Lazy<(ark_bn254::Fq, ark_bn254::Fr)> =
            Lazy::new(endos::<ark_bn254::G1Affine>);
        &ENDOS
    }

    fn other_curve_endo() -> &'static Self::ScalarField {
        // TODO: Dummy value, this is definitely not right
        static ENDO: Lazy<ark_bn254::Fr> = Lazy::new(|| 13u64.into());
        &ENDO
    }

    fn other_curve_generator() -> (Self::ScalarField, Self::ScalarField) {
        // TODO: Dummy value, this is definitely not right
        (44u64.into(), 88u64.into())
    }
}

////////////////////////////////////////////////////////////////////////////
// WASM
////////////////////////////////////////////////////////////////////////////

impl KimchiCurve for Affine<WasmPallasParameters> {
    const NAME: &'static str = "pallas_wasm";

    fn sponge_params() -> &'static ArithmeticSpongeParams<Self::ScalarField> {
        todo!()
        //mina_poseidon::pasta::fq_kimchi::static_params()
    }

    fn other_curve_sponge_params() -> &'static ArithmeticSpongeParams<Self::BaseField> {
        todo!()
        //mina_poseidon::pasta::fp_kimchi::static_params()
    }

    fn endos() -> &'static (Self::BaseField, Self::ScalarField) {
        todo!()
        //pallas_endos()
    }

    fn other_curve_endo() -> &'static Self::ScalarField {
        todo!()
        //&vesta_endos().0
    }

    fn other_curve_prime_subgroup_generator() -> (Self::ScalarField, Self::ScalarField) {
        todo!()
        //Affine::<VestaParameters>::generator()
        //    .to_coordinates()
        //    .unwrap()
    }
}
