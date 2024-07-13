use std::collections::BTreeMap;

use folding::{FoldingConfig, FoldingOutput};
use mina_poseidon::poseidon::SpongeState;

/// An environment that can be shared between IVC instances
/// It contains all the accumulators that can be picked for a given fold
/// instance k, including the sponges.
/// For each fold instance k, the prover will pick one accumulator to merge with
/// the current instance.
pub struct Env<C: FoldingConfig> {
    /// Accumulators, indexed by natural numbers, but it should be an
    /// instruction or an enum representing a list of accepting "functions".
    pub accumulators: BTreeMap<usize, FoldingOutput<C>>,

    /// Sponges, index by natural numbers. The natural numbers should be the
    /// instruction.
    /// We keep one sponge state by isntruction and when we merge different
    /// instructions, we can use the different sponges states to compute a new
    /// global one.
    pub sponges: BTreeMap<usize, SpongeState>,
}
