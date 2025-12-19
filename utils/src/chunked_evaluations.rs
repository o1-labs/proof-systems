//! This module contains a type [ChunkedEvaluations],

#[cfg(feature = "no-std")]
use alloc::vec::Vec;

use ark_ff::PrimeField;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

/// This struct contains multiple chunk evaluations.
#[serde_as]
#[derive(Clone, Serialize, Deserialize)]
pub struct ChunkedEvaluations<F>
where
    F: PrimeField,
{
    /// The chunk evaluations.
    #[serde_as(as = "Vec<crate::serialization::SerdeAs>")]
    pub chunks: Vec<F>,

    /// Each chunk polynomial has degree `size-1`.
    pub size: usize,
}
