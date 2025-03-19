use once_cell::sync::OnceCell;
use serde::{ser, Deserialize, Serialize, Serializer};
use std::{
    fmt,
    sync::{Arc, Mutex},
};

/// A memory-efficient container that either stores a cached value or computes it on demand.
///
/// `LazyCache<T>` optimizes memory and computation by either:
/// - Storing a **precomputed** value in the `Cached` variant.
/// - Storing a **computation function** in the `OnDemand` variant, which computes the value
///   only when first accessed, then transitions to `Cached` to avoid recomputation.
///
pub enum LazyCache<T> {
    /// Precomputed value
    Cached(OnceCell<T>),

    /// Deferred computation that is evaluated only once when accessed
    Lazy {
        // The value once computed
        computed: OnceCell<T>,
        // The function to compute the value
        compute_fn: Mutex<Option<Arc<dyn Fn() -> T + Send + Sync>>>,
    },
}

impl<T> LazyCache<T> {
    // Create a new `LazyCache` with a cached computation
    pub fn cache(value: T) -> Self {
        let cell = OnceCell::new();
        let _ = cell.set(value);
        LazyCache::Cached(cell)
    }

    // Create a new `LazyCache` with a deferred computation
    pub fn lazy(compute_fn: impl Fn() -> T + Send + Sync + 'static) -> Self {
        LazyCache::Lazy {
            computed: OnceCell::new(),
            compute_fn: Mutex::new(Some(Arc::new(compute_fn))),
        }
    }

    /// Returns a reference, computing and caching if necessary.
    pub fn get(&self) -> &T {
        match self {
            LazyCache::Cached(value) => value.get().unwrap(),
            LazyCache::Lazy {
                computed,
                compute_fn,
            } => computed.get_or_init(|| {
                compute_fn
                    .lock()
                    .unwrap()
                    .take()
                    .expect("no function inside LazyCache::Lazy")()
            }),
        }
    }
}

impl<T> fmt::Debug for LazyCache<T>
where
    T: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LazyCache::Cached(value) => f.debug_tuple("Cached").field(value).finish(),
            LazyCache::Lazy { .. } => f.write_str("Lazy { <function> }"),
        }
    }
}

impl<T> Default for LazyCache<T> {
    fn default() -> Self {
        LazyCache::Cached { 0: OnceCell::new() }
    }
}

impl<T> Clone for LazyCache<T>
where
    T: Clone,
{
    fn clone(&self) -> Self {
        match self {
            LazyCache::Cached(value) => LazyCache::Cached(value.clone()),
            LazyCache::Lazy {
                computed,
                compute_fn,
            } => LazyCache::Lazy {
                computed: computed.clone(),
                compute_fn: Mutex::new(compute_fn.lock().unwrap().as_ref().map(Arc::clone)),
            },
        }
    }
}

impl<T> Serialize for LazyCache<T>
where
    T: Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            LazyCache::Cached(cell) => cell
                .get()
                .ok_or_else(|| serde::ser::Error::custom("LazyCache::Cached is uninitialized"))?
                .serialize(serializer),
            LazyCache::Lazy { computed, .. } => computed.get().map_or_else(
                || Err(ser::Error::custom("LazyCache:Lazy is not computed")),
                |value| value.serialize(serializer),
            ),
        }
    }
}

impl<'de, T> Deserialize<'de> for LazyCache<T>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let maybe_value = Option::<T>::deserialize(deserializer)?;
        Ok(match maybe_value {
            Some(value) => {
                let cell = OnceCell::new();
                let _ = cell.set(value);
                LazyCache::Cached(cell)
            }
            None => LazyCache::Lazy {
                computed: OnceCell::new(),
                compute_fn: Mutex::new(None),
            },
        })
    }
}
