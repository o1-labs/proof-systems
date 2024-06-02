use ark_ec::{short_weierstrass::Affine, CurveConfig};
use mina_curves::pasta::curves::{
    pallas::{LegacyPallasParameters, PallasParameters},
    vesta::{LegacyVestaParameters, VestaParameters},
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

impl KimchiCurve for Affine<VestaParameters> {
    type OtherCurve = Affine<PallasParameters>;

    fn sponge_params() -> &'static ArithmeticSpongeParams<Self::ScalarField> {
        mina_poseidon::pasta::fp_kimchi::static_params()
    }

    fn endos() -> &'static (Self::BaseField, Self::ScalarField) {
        static VESTA_ENDOS: Lazy<(
            <VestaParameters as CurveConfig>::BaseField,
            <VestaParameters as CurveConfig>::ScalarField,
        )> = Lazy::new(endos::<Affine<VestaParameters>>);
        &VESTA_ENDOS
    }
}

impl KimchiCurve for Affine<PallasParameters> {
    type OtherCurve = Affine<VestaParameters>;

    fn sponge_params() -> &'static ArithmeticSpongeParams<Self::ScalarField> {
        mina_poseidon::pasta::fq_kimchi::static_params()
    }

    fn endos() -> &'static (Self::BaseField, Self::ScalarField) {
        static PALLAS_ENDOS: Lazy<(
            <PallasParameters as CurveConfig>::BaseField,
            <PallasParameters as CurveConfig>::ScalarField,
        )> = Lazy::new(endos::<Affine<PallasParameters>>);
        &PALLAS_ENDOS
    }
}

//
// legacy curves
//

impl KimchiCurve for Affine<LegacyVestaParameters> {
    type OtherCurve = Affine<LegacyPallasParameters>;

    fn sponge_params() -> &'static ArithmeticSpongeParams<Self::ScalarField> {
        mina_poseidon::pasta::fp_legacy::static_params()
    }

    fn endos() -> &'static (Self::BaseField, Self::ScalarField) {
        Affine::<VestaParameters>::endos()
    }
}
impl KimchiCurve for Affine<LegacyPallasParameters> {
    type OtherCurve = Affine<LegacyVestaParameters>;

    fn sponge_params() -> &'static ArithmeticSpongeParams<Self::ScalarField> {
        mina_poseidon::pasta::fq_legacy::static_params()
    }

    fn endos() -> &'static (Self::BaseField, Self::ScalarField) {
        Affine::<PallasParameters>::endos()
    }
}
