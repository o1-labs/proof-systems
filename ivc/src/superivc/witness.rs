use std::collections::BTreeMap;

use ark_ec::AffineCurve;
use folding::{FoldingConfig, FoldingOutput};
use mina_poseidon::{constants::SpongeConstants, poseidon::ArithmeticSponge};
use poly_commitment::PolyComm;

/// An environment that can be shared between IVC instances
/// It contains all the accumulators that can be picked for a given fold
/// instance k, including the sponges.
/// For each fold instance k, the prover will pick one accumulator to merge with
/// the current instance.
/// We split the accumulators between the ones used by the applications and the one
/// for the IVC.
/// It is parametrized by:
/// - FCAPP: a folding configuration specific for the application
/// - FCIVC: a folding configuration specific for the IVC circuit only
/// - N_APP_COL: the number of columns used by the applications. It does suppose
/// all applications use the same number of columns
// FIXME: constrain the curve, field, etc to be the same
// FIXME: instead of indexing by usize, it would be nice to have a type
// "instruction" or "application" that can be later generalized. It could simply
// be an enum.
pub struct Env<
    SpongeConfig: SpongeConstants,
    FCApp: FoldingConfig,
    FCIVC: FoldingConfig<Curve = FCApp::Curve, Srs = FCApp::Srs>,
    const N_APP_COL: usize,
> {
    /// IVC accumulators, indexed by natural numbers, but it should be an
    /// instruction or an enum representing a list of accepting "functions".
    pub ivc_accumulators: BTreeMap<usize, FoldingOutput<FCIVC>>,

    /// Accumulators of the applications
    pub app_accumulators: BTreeMap<usize, FoldingOutput<FCApp>>,

    /// Sponges, index by natural numbers. The natural numbers should be the
    /// instruction.
    /// We keep one sponge state by isntruction and when we merge different
    /// instructions, we can use the different sponges states to compute a new
    /// global one.
    pub sponges: BTreeMap<
        usize,
        ArithmeticSponge<
            <<FCApp as FoldingConfig>::Curve as AffineCurve>::ScalarField,
            SpongeConfig,
        >,
    >,

    /// Contains the current application instance that will be folded with
    pub current_app_instance: [PolyComm<FCApp::Curve>; N_APP_COL],
}

impl<
        SpongeConfig: SpongeConstants,
        FCApp: FoldingConfig,
        FCIVC: FoldingConfig<Curve = FCApp::Curve, Srs = FCApp::Srs>,
        const N_APP_COL: usize,
    > Env<SpongeConfig, FCApp, FCIVC, N_APP_COL>
{
    pub fn set_current_app_instance(&mut self, instance: [PolyComm<FCApp::Curve>; N_APP_COL]) {
        self.current_app_instance = instance
    }

    /// Return the output of the application.
    /// We define the output as the first element of the sponge specialised for
    /// the application, after absorbing all the commitments of the current app
    /// instance being processed
    pub fn get_application_output(
        &self,
        instruction: usize,
    ) -> <<FCApp as FoldingConfig>::Curve as AffineCurve>::ScalarField {
        self.sponges[&instruction].state[0]
    }
}
