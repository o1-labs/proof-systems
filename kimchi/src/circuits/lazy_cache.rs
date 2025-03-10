use once_cell::sync::OnceCell;
use serde::{Deserialize, Serialize};
use std::{fmt, sync::Arc};

/// A memory-efficient container that caches or computes `T` on demand.
#[derive(Clone, Serialize)]
pub enum LazyCache<T>
where
    T: Send + Sync,
{
    /// Precomputed value
    // TODO: Cached(OnceCell<T>),?
    Cached(T),

    /// Deferred computation that is evaluated only once when accessed
    #[serde(skip)]
    Lazy {
        // The value once computed
        computed: OnceCell<T>,
        // The function to compute the value
        compute_fn: Option<Arc<dyn Fn() -> T + Send + Sync>>,
    },
}

/// A memory-efficient container that either stores a cached value or computes it on demand.
///
/// `LazyCache<T>` optimizes memory and computation by either:
/// - Storing a **precomputed** value in the `Cached` variant.
/// - Storing a **computation function** in the `OnDemand` variant, which computes the value
///   only when first accessed, then transitions to `Cached` to avoid recomputation.
///
impl<T> LazyCache<T>
where
    T: Send + Sync,
{
    // Create a new `LazyCache` with a cached computation
    pub fn cache(value: T) -> Self {
        LazyCache::Cached(value)
    }

    // Create a new `LazyCache` with a deferred computation
    pub fn lazy(compute_fn: impl Fn() -> T + Send + Sync + 'static) -> Self {
        LazyCache::Lazy {
            computed: OnceCell::new(),
            compute_fn: Some(Arc::new(compute_fn)),
        }
    }

    /// Returns a reference, computing and caching if necessary.
    pub fn get(&self) -> &T {
        match self {
            LazyCache::Cached(value) => value,
            LazyCache::Lazy {
                computed,
                compute_fn,
            } => computed.get_or_init(|| {
                let result = compute_fn
                    .as_ref()
                    .expect("no function inside LazyCache::Lazy")(); // Compute value
                                                                     // After initialization, remove `compute_fn` (workaround for interior mutability)
                unsafe {
                    let mut_self = self as *const _ as *mut Self;
                    if let LazyCache::Lazy { compute_fn, .. } = &mut *mut_self {
                        *compute_fn = None; // Remove reference to `cs`
                    }
                }
                result
            }),
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
            LazyCache::Lazy { .. } => f.write_str("Lazy { <function> }"),
        }
    }
}

impl<T> Default for LazyCache<T>
where
    T: Send + Sync,
{
    fn default() -> Self {
        LazyCache::Lazy {
            computed: OnceCell::new(),
            compute_fn: None,
        }
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
            None => LazyCache::Lazy {
                computed: OnceCell::new(),
                compute_fn: None,
            },
        })
    }
}
