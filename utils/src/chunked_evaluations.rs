//! This module contains a type [ChunkedEvaluations],

use serde::{Deserialize, Serialize};
use serde_with::serde_as;

/// This struct contains multiple chunk evaluations.
#[serde_as]
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound = "F: ark_serialize::CanonicalDeserialize + ark_serialize::CanonicalSerialize")]
pub struct ChunkedEvaluations<F> {
    /// The chunk evaluations.
    #[serde_as(as = "Vec<crate::serialization::SerdeAs>")]
    pub chunks: Vec<F>,

    /// Each chunk polynomial has degree `size-1`.
    pub size: usize,
}
