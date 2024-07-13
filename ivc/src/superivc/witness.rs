use std::collections::BTreeMap;

use folding::{FoldingConfig, FoldingOutput};
use mina_poseidon::poseidon::SpongeState;

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
pub struct Env<FCApp: FoldingConfig, FCIVC: FoldingConfig, const N_APP_COL: usize> {
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
    pub sponges: BTreeMap<usize, SpongeState>,
}
