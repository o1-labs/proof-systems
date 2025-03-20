use serde::{de::DeserializeOwned, Deserialize, Serialize, Serializer};
use std::sync::LazyLock;

trait SendSyncFunction<T>: FnOnce() -> T + Send + Sync + 'static {}

impl<T, U> SendSyncFunction<T> for U
where
    U: FnOnce() -> T + Send + Sync + 'static,
    T: Send + Sync + 'static,
{
}

/// A memory-efficient container that either stores a cached value or computes it on demand.
///
/// `LazyCache<T>` optimizes memory and computation by either:
/// - Storing a **precomputed** value in the `Cached` variant.
/// - Storing a **computation function** in the `OnDemand` variant, which computes the value
///   only when first accessed, then transitions to `Cached` to avoid recomputation.
///
#[derive(Debug)]
pub struct LazyCache<T> {
    // The value once computed
    computed: LazyLock<T, Box<dyn SendSyncFunction<T>>>,
}

impl<T: Send + Sync + 'static> LazyCache<T> {
    // Create a new `LazyCache` with a cached computation
    pub fn cache(value: T) -> Self {
        let f = move || value;
        Self {
            computed: LazyLock::new(Box::new(f)),
        }
    }

    // Create a new `LazyCache` with a deferred computation
    pub fn lazy<F>(compute_fn: F) -> Self
    where
        F: FnOnce() -> T + Send + Sync + 'static,
    {
        Self {
            computed: LazyLock::new(Box::new(compute_fn)),
        }
    }

    /// Returns a reference, computing and caching if necessary.
    pub fn get(&self) -> &T {
        &*self.computed
    }
}

impl<T> Default for LazyCache<T>
where
    T: Default + Send + Sync + 'static,
{
    fn default() -> Self {
        Self::cache(T::default())
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
    // Deserializing will create a `LazyCache` with a cached value
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = T::deserialize(deserializer)?;
        Ok(LazyCache::cache(value))
    }
}
