use ark_ec::{short_weierstrass::Affine, CurveConfig};
use mina_curves::pasta::curves::{
    pallas::{LegacyPallasConfig, PallasConfig},
    vesta::{LegacyVestaConfig, VestaConfig},
};
use mina_poseidon::poseidon::ArithmeticSpongeParams;
use once_cell::sync::Lazy;
use poly_commitment::{commitment::CommitmentCurve, srs::endos};

///Represents additional information that a curve needs in order to be used with Kimchi
pub trait KimchiCurve: CommitmentCurve {
    /// The other curve that forms the cycle used for recursion
    type OtherCurve: KimchiCurve<
        ScalarField = Self::BaseField,
        BaseField = Self::ScalarField,
        OtherCurve = Self,
    >;

    /// Provides the sponge params to be used with this curve
    /// If the params for the base field are needed, they can be obtained from [`KimchiCurve::OtherCurve`]
    fn sponge_params() -> &'static ArithmeticSpongeParams<Self::ScalarField>;

    /// Provides the coefficients for the curve endomorphism
    // called (q,r) in some places
    fn endos() -> &'static (Self::BaseField, Self::ScalarField);
}

impl KimchiCurve for Affine<VestaConfig> {
    type OtherCurve = Affine<PallasConfig>;

    fn sponge_params() -> &'static ArithmeticSpongeParams<Self::ScalarField> {
        mina_poseidon::pasta::fp_kimchi::static_params()
    }

    fn endos() -> &'static (Self::BaseField, Self::ScalarField) {
        static VESTA_ENDOS: Lazy<(
            <VestaConfig as CurveConfig>::BaseField,
            <VestaConfig as CurveConfig>::ScalarField,
        )> = Lazy::new(endos::<Affine<VestaConfig>>);
        &VESTA_ENDOS
    }
}

impl KimchiCurve for Affine<PallasConfig> {
    type OtherCurve = Affine<VestaConfig>;

    fn sponge_params() -> &'static ArithmeticSpongeParams<Self::ScalarField> {
        mina_poseidon::pasta::fq_kimchi::static_params()
    }

    fn endos() -> &'static (Self::BaseField, Self::ScalarField) {
        static PALLAS_ENDOS: Lazy<(
            <PallasConfig as CurveConfig>::BaseField,
            <PallasConfig as CurveConfig>::ScalarField,
        )> = Lazy::new(endos::<Affine<PallasConfig>>);
        &PALLAS_ENDOS
    }
}

//
// legacy curves
//

impl KimchiCurve for Affine<LegacyVestaConfig> {
    type OtherCurve = Affine<LegacyPallasConfig>;

    fn sponge_params() -> &'static ArithmeticSpongeParams<Self::ScalarField> {
        mina_poseidon::pasta::fp_legacy::static_params()
    }

    fn endos() -> &'static (Self::BaseField, Self::ScalarField) {
        Affine::<VestaConfig>::endos()
    }
}
impl KimchiCurve for Affine<LegacyPallasConfig> {
    type OtherCurve = Affine<LegacyVestaConfig>;

    fn sponge_params() -> &'static ArithmeticSpongeParams<Self::ScalarField> {
        mina_poseidon::pasta::fq_legacy::static_params()
    }

    fn endos() -> &'static (Self::BaseField, Self::ScalarField) {
        Affine::<PallasConfig>::endos()
    }
}
