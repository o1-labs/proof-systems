use serde::{Deserialize, Serialize};
use std::{fmt, sync::Arc};

#[derive(Clone, Serialize)]
pub enum LazyCache<T>
where
    T: Send + Sync,
{
    Cached(T),
    #[serde(skip)]
    OnDemand {
        // The function to compute the value
        compute_fn: Option<Arc<dyn Fn() -> T + Send + Sync>>,
    },
}

/// A memory-efficient container that either stores a cached value or computes it on demand.
///
/// `LazyCache<T, F>` optimizes memory and computation by either:
/// - Storing a **precomputed** value in the `Cached` variant.
/// - Storing a **computation function** in the `OnDemand` variant, which computes the value
///   only when first accessed, then transitions to `Cached` to avoid recomputation.
///
impl<T> LazyCache<T>
where
    T: Send + Sync,
{
    /// Returns a reference, computing and caching if necessary.
    pub fn get(&mut self) -> &T {
        if let LazyCache::OnDemand { compute_fn } = self {
            if let Some(fn_ptr) = compute_fn.as_ref() {
                let computed_value = (fn_ptr)(); // Compute the result
                *self = LazyCache::Cached(computed_value); // Store it permanently
            } else {
                panic!("LazyCache::OnDemand::compute_fn is None");
            }
        }

        match self {
            LazyCache::Cached(value) => value,
            _ => unreachable!(), // Should never happen
        }
    }
}

impl<T> fmt::Debug for LazyCache<T>
where
    T: fmt::Debug + Send + Sync,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LazyCache::Cached(value) => f.debug_tuple("Cached").field(value).finish(),
            LazyCache::OnDemand { .. } => f.write_str("OnDemand { <function> }"),
        }
    }
}

impl<T> Default for LazyCache<T>
where
    T: Send + Sync,
{
    fn default() -> Self {
        LazyCache::OnDemand { compute_fn: None }
    }
}

impl<'de, T> Deserialize<'de> for LazyCache<T>
where
    T: Deserialize<'de> + Send + Sync,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let maybe_value = Option::<T>::deserialize(deserializer)?;
        Ok(match maybe_value {
            Some(value) => LazyCache::Cached(value),
            None => LazyCache::OnDemand { compute_fn: None },
        })
    }
}
