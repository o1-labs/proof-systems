use crate::circuits::constraints::FeatureFlags;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

/// A serializable fixture that bundles a proof, verifier index, public inputs,
/// and the feature flags needed to reconstruct `linearization` / `powers_of_alpha`.
///
/// `proof_bytes` and `verifier_index_bytes` are msgpack-serialized.
/// `public_inputs_bytes` uses ark's `CanonicalSerialize` since field elements
/// don't implement serde's `Serialize`/`Deserialize` directly.
#[derive(Serialize, Deserialize)]
pub struct RawFixture {
    pub proof_bytes: Vec<u8>,
    pub verifier_index_bytes: Vec<u8>,
    pub public_inputs_bytes: Vec<u8>,
    pub num_public_inputs: usize,
    pub feature_flags: FeatureFlags,
}
