use once_cell::sync::OnceCell;
use serde::{de::DeserializeOwned, Deserialize, Serialize, Serializer};
use std::{
    fmt,
    sync::{Arc, Mutex},
};

type LazyFn<T> = Box<dyn FnOnce() -> T + Send + Sync + 'static>;
type LockedLazyFn<T> = Arc<Mutex<Option<LazyFn<T>>>>;

/// A memory-efficient container that either stores a cached value or computes it on demand.
///
/// `LazyCache<T>` optimizes memory and computation by either:
/// - Storing a **precomputed** value in the `Cached` variant.
/// - Storing a **computation function** in the `Lazy` variant, which computes the value
///   only when first accessed, then stores the value in `computed` to avoid recomputation
///   and the function is dropped.
///
pub enum LazyCache<T> {
    /// Precomputed value
    Cached(OnceCell<T>),

    /// Deferred computation that is evaluated only once when accessed
    Lazy {
        // The value once computed
        computed: OnceCell<T>,
        // The function to compute the value
        compute_fn: LockedLazyFn<T>,
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
    pub fn lazy(compute_fn: impl FnOnce() -> T + Send + Sync + 'static) -> Self {
        LazyCache::Lazy {
            computed: OnceCell::new(),
            compute_fn: Arc::new(Mutex::new(Some(Box::new(compute_fn)))),
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
                // When `computed` is empty, that means the function was not used.
                // First we lock the access to the function, move out the function
                // from memory and then call and consume it. The result is stored
                // in `computed` and the function is dropped.
                compute_fn
                    .lock()
                    .unwrap()
                    .take()
                    .expect("No function inside LazyCache::Lazy")()
            }),
        }
    }
}

impl<T: Clone> Clone for LazyCache<T> {
    fn clone(&self) -> Self {
        match self {
            LazyCache::Cached(value) => LazyCache::Cached(value.clone()),

            LazyCache::Lazy {
                computed,
                compute_fn,
            } => LazyCache::Lazy {
                computed: computed.clone(),
                // This will clone references to `compute_fn`, but the function
                // itself will be executed only once when accessed.
                compute_fn: Arc::clone(compute_fn),
            },
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
        LazyCache::Cached(OnceCell::new())
    }
}

impl<T> Serialize for LazyCache<T>
where
    T: Serialize + Send + Sync + 'static,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.get().serialize(serializer)
    }
}

impl<'de, T> Deserialize<'de> for LazyCache<T>
where
    T: DeserializeOwned + Send + Sync + 'static,
{
    // Deserializing will create a `LazyCache` with a cached value or an error
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = T::deserialize(deserializer)?;
        Ok(LazyCache::cache(value))
    }
}
