use std::collections::BTreeMap;

use folding::{FoldingConfig, FoldingOutput};
use mina_poseidon::poseidon::SpongeState;

pub struct Env<C: FoldingConfig> {
    /// Accumulators, indexed by natural numbers, but it should be an
    /// instruction or an enum representing a list of accepting "functions".
    pub accumulators: BTreeMap<usize, FoldingOutput<C>>,

    pub sponges: BTreeMap<usize, SpongeState>,
}
