use ark_ec::{short_weierstrass_jacobian::GroupAffine, ModelParameters};
use commitment_dlog::{commitment::CommitmentCurve, srs::endos};
use mina_curves::pasta::{
    curves::{
        pallas::{LegacyPallas, PallasParameters},
        vesta::{LegacyVesta, VestaParameters},
    },
    Pallas, Vesta,
};
use mina_poseidon::poseidon::ArithmeticSpongeParams;
use o1_utils::fast_msm::msm::MultiScalarMultiplication;
use once_cell::sync::Lazy;

///Represents additional information that a curve needs in order to be used with Kimchi
pub trait KimchiCurve: CommitmentCurve + MultiScalarMultiplication {
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

impl KimchiCurve for Vesta {
    type OtherCurve = Pallas;

    fn sponge_params() -> &'static ArithmeticSpongeParams<Self::ScalarField> {
        mina_poseidon::pasta::fp_kimchi::static_params()
    }

    fn endos() -> &'static (Self::BaseField, Self::ScalarField) {
        static VESTA_ENDOS: Lazy<(
            <VestaParameters as ModelParameters>::BaseField,
            <VestaParameters as ModelParameters>::ScalarField,
        )> = Lazy::new(endos::<Vesta>);
        &VESTA_ENDOS
    }
}

impl KimchiCurve for Pallas {
    type OtherCurve = Vesta;

    fn sponge_params() -> &'static ArithmeticSpongeParams<Self::ScalarField> {
        mina_poseidon::pasta::fq_kimchi::static_params()
    }

    fn endos() -> &'static (Self::BaseField, Self::ScalarField) {
        static PALLAS_ENDOS: Lazy<(
            <PallasParameters as ModelParameters>::BaseField,
            <PallasParameters as ModelParameters>::ScalarField,
        )> = Lazy::new(endos::<Pallas>);
        &PALLAS_ENDOS
    }
}

//
// legacy curves
//

impl KimchiCurve for LegacyVesta {
    type OtherCurve = LegacyPallas;

    fn sponge_params() -> &'static ArithmeticSpongeParams<Self::ScalarField> {
        mina_poseidon::pasta::fp_legacy::static_params()
    }

    fn endos() -> &'static (Self::BaseField, Self::ScalarField) {
        GroupAffine::<VestaParameters>::endos()
    }
}

impl KimchiCurve for LegacyPallas {
    type OtherCurve = LegacyVesta;

    fn sponge_params() -> &'static ArithmeticSpongeParams<Self::ScalarField> {
        mina_poseidon::pasta::fq_legacy::static_params()
    }

    fn endos() -> &'static (Self::BaseField, Self::ScalarField) {
        GroupAffine::<PallasParameters>::endos()
    }
}
