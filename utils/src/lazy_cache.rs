#![allow(unsafe_code)]
//! Polyfill of the `LazyLock` type in the std library as of Rust 1.80.
//!
//! The current file should be deleted soon, as we now support Rust 1.81 and
//! use the official `LazyLock`, and [`LazyCache`] as a wrapper around `LazyLock`
//! to allow for custom serialization definitions.

use core::{fmt, ops::Deref};
use serde::{de::DeserializeOwned, Deserialize, Serialize, Serializer};

#[cfg(feature = "std")]
use alloc::boxed::Box;
#[cfg(feature = "std")]
type LazyFn<T> = Box<dyn FnOnce() -> T + Send + Sync + 'static>;
#[cfg(feature = "std")]
use std::sync::{
    atomic::{AtomicBool, Ordering},
    LazyLock,
};

/// A thread-safe, lazily-initialized value.
pub struct LazyCache<T> {
    #[cfg(not(feature = "std"))]
    value: T,
    #[cfg(feature = "std")]
    initialized: AtomicBool,
    #[cfg(feature = "std")]
    lazy_value: LazyLock<T, LazyFn<T>>,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum LazyCacheError {
    LockPoisoned,
    UninitializedCache,
    MissingFunctionOrInitializedTwice,
}

#[derive(Debug, PartialEq, Eq)]
pub enum LazyCacheErrorOr<E> {
    Inner(E),
    Outer(LazyCacheError),
}

// We never create a `&F` from a `&LazyCache<T, F>` so it is fine
// to not impl `Sync` for `F`.
unsafe impl<T: Send + Sync> Sync for LazyCache<T> {}
unsafe impl<T: Send> Send for LazyCache<T> {}

impl<T> LazyCache<T> {
    pub fn new<F>(f: F) -> Self
    where
        F: FnOnce() -> T + Send + Sync + 'static,
    {
        #[cfg(feature = "std")]
        {
            Self {
                initialized: false.into(),
                lazy_value: LazyLock::new(Box::new(f)),
            }
        }
        #[cfg(not(feature = "std"))]
        {
            Self { value: f() }
        }
    }
}

#[cfg(feature = "std")]
impl<T> LazyCache<T> {
    /// # Panics
    ///
    /// Panics if initialization fails or the cache is poisoned.
    pub fn get(&self) -> &T {
        // best effort
        self.initialized.store(true, Ordering::Relaxed);
        LazyLock::force(&self.lazy_value)
    }
}

#[cfg(feature = "std")]
impl<T: Send + Sync + 'static> LazyCache<T> {
    #[allow(clippy::nursery)]
    /// Creates a new lazy value that is already initialized.
    pub fn preinit(value: T) -> Self {
        let lazy_value = LazyLock::new(Box::new(move || value) as LazyFn<T>);
        LazyLock::force(&lazy_value);
        Self {
            initialized: true.into(),
            lazy_value,
        }
    }
}

#[cfg(not(feature = "std"))]
impl<T> LazyCache<T> {
    #[allow(clippy::nursery)]
    /// Creates a new lazy value that is already initialized.
    pub fn preinit(value: T) -> Self {
        Self { value }
    }

    pub const fn get(&self) -> &T {
        &self.value
    }
}

impl<T> Deref for LazyCache<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.get()
    }
}

impl<T: fmt::Debug> fmt::Debug for LazyCache<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        #[cfg(feature = "std")]
        // best effort
        if !self.initialized.load(Ordering::Relaxed) {
            return f.write_str("LazyCache(<uninitialized>)");
        }

        f.debug_tuple("LazyCache").field(self.get()).finish()
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
        Ok(Self::preinit(value))
    }
}

#[cfg(all(test, feature = "std"))]
// Unit tests for LazyCache
mod test {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[cfg(all(not(target_arch = "wasm32"), feature = "diagnostics"))]
    fn print_heap_usage(label: &str) {
        use tikv_jemalloc_ctl::{epoch, stats};

        epoch::advance().unwrap(); // refresh internal stats!
        let allocated = stats::allocated::read().unwrap();
        println!("[{label}] Heap allocated: {} kilobytes", allocated / 1024);
    }

    #[test]
    fn test_preinit_get() {
        let cache = LazyCache::preinit(100);
        assert_eq!(*cache.get(), 100);
    }

    #[test]
    fn test_lazy_get() {
        let lazy = LazyCache::new(|| {
            let a = 10;
            let b = 20;
            a + b
        });
        assert_eq!(*lazy.get(), 30);
        // Ensure the value is cached and can be accessed multiple times
        assert_eq!(*lazy.get(), 30);
    }

    #[test]
    fn test_function_called_only_once() {
        let counter = Arc::new(Mutex::new(0));
        let counter_clone = Arc::clone(&counter);

        let cache = LazyCache::new(move || {
            let mut count = counter_clone.lock().unwrap();
            *count += 1;
            99
        });

        assert_eq!(*cache.get(), 99);
        assert_eq!(*cache.get(), 99); // Ensure cached
        assert_eq!(*counter.lock().unwrap(), 1); // Function was called exactly once
    }

    #[test]
    fn test_serde() {
        let cache = LazyCache::preinit(10);
        let serialized = serde_json::to_string(&cache).unwrap();
        let deserialized: LazyCache<i32> = serde_json::from_str(&serialized).unwrap();
        assert_eq!(*deserialized.get(), 10);
    }

    #[test]
    fn test_debug() {
        let cache = LazyCache::preinit(10);
        assert_eq!(format!("{cache:?}"), "LazyCache(10)");

        let lazy = LazyCache::new(|| 20);
        assert_eq!(format!("{lazy:?}"), "LazyCache(<uninitialized>)");
    }

    #[cfg(all(not(target_arch = "wasm32"), feature = "diagnostics"))]
    #[test]
    fn test_lazy_cache_allocation() {
        use tikv_jemallocator::Jemalloc;

        #[global_allocator]
        static GLOBAL: Jemalloc = Jemalloc;

        print_heap_usage("Start");

        let cache = Arc::new(LazyCache::new(|| vec![42u8; 1024 * 1024])); // 1MB

        print_heap_usage("Before initializing LazyCache");

        let _ = cache.get();

        print_heap_usage("After initializing LazyCache");
    }
}
