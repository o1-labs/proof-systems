//! This is a polyfill of the `LazyLock` type in the std library as of Rust 1.80.
//! The current file should be deleted as soon as we support Rust >1.79 and
//! use the official `LazyLock` type when available, and `LazyCache` as a
//! wrapper around `LazyLock` to allow for serialization definitions.

use serde::{de::DeserializeOwned, Deserialize, Serialize, Serializer};
use std::{cell::UnsafeCell, fmt, ops::Deref, sync::Once};

type LazyFn<T> = Box<dyn FnOnce() -> T + Send + Sync + 'static>;

/// A thread-safe, lazily-initialized value.
pub struct LazyCache<T> {
    pub(crate) once: Once,
    pub(crate) value: UnsafeCell<Option<T>>,
    pub(crate) init: UnsafeCell<Option<LazyFn<T>>>,
}

#[derive(Debug, PartialEq, Clone)]
pub enum LazyCacheError {
    LockPoisoned,
    UninitializedCache,
    MissingFunctionOrInitializedTwice,
}

#[derive(Debug, PartialEq)]
pub enum LazyCacheErrorOr<E> {
    Inner(E),
    Outer(LazyCacheError),
}

// We never create a `&F` from a `&LazyCache<T, F>` so it is fine
// to not impl `Sync` for `F`.
unsafe impl<T: Send + Sync> Sync for LazyCache<T> {}
unsafe impl<T: Send> Send for LazyCache<T> {}

// auto-derived `Send` impl is OK.
//unsafe impl<T: Send, F: Send> Send for LazyCache<T, F> {}

impl<T> LazyCache<T> {
    pub fn new<F>(f: F) -> Self
    where
        F: FnOnce() -> T + Send + Sync + 'static,
    {
        LazyCache {
            once: Once::new(),
            value: UnsafeCell::new(None),
            init: UnsafeCell::new(Some(Box::new(f))),
        }
    }

    /// Creates a new lazy value that is already initialized.
    pub fn preinit(value: T) -> LazyCache<T> {
        let once = Once::new();
        once.call_once(|| {});
        LazyCache {
            once,
            value: UnsafeCell::new(Some(value)),
            init: UnsafeCell::new(None),
        }
    }

    fn try_initialize(&self) -> Result<(), LazyCacheError> {
        let mut error = None;

        self.once.call_once_force(|state| {
            if state.is_poisoned() {
                error = Some(LazyCacheError::LockPoisoned);
                return;
            }

            let init_fn = unsafe { (*self.init.get()).take() };
            match init_fn {
                Some(f) => {
                    let value = f();
                    unsafe {
                        *self.value.get() = Some(value);
                    }
                }
                None => {
                    error = Some(LazyCacheError::MissingFunctionOrInitializedTwice);
                }
            }
        });

        if let Some(e) = error {
            return Err(e);
        }

        if self.once.is_completed() {
            Ok(())
        } else {
            Err(LazyCacheError::LockPoisoned)
        }
    }

    pub(crate) fn try_get(&self) -> Result<&T, LazyCacheError> {
        self.try_initialize()?;
        unsafe {
            (*self.value.get())
                .as_ref()
                .ok_or(LazyCacheError::UninitializedCache)
        }
    }

    pub fn get(&self) -> &T {
        self.try_get().unwrap()
    }
}

// Wrapper to support cases where the init function might return an error that
// needs to be handled separately (for example, LookupConstraintSystem::crate())
impl<T, E: Clone> LazyCache<Result<T, E>> {
    pub fn try_get_or_err(&self) -> Result<&T, LazyCacheErrorOr<E>> {
        match self.try_get() {
            Ok(Ok(v)) => Ok(v),
            Ok(Err(e)) => Err(LazyCacheErrorOr::Inner(e.clone())),
            Err(_) => Err(LazyCacheErrorOr::Outer(LazyCacheError::LockPoisoned)),
        }
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
        // SAFETY: It's safe to access self.value here, read-only
        let value = unsafe { &*self.value.get() };
        match value {
            Some(v) => f.debug_tuple("LazyCache").field(v).finish(),
            None => f.write_str("LazyCache(<uninitialized>)"),
        }
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
        Ok(LazyCache::preinit(value))
    }
}

#[cfg(test)]
// Unit tests for LazyCache
mod test {
    use super::*;
    use std::{
        sync::{Arc, Mutex},
        thread,
    };
    use jemalloc_ctl::{epoch, stats};
    use jemallocator::Jemalloc;

    fn print_heap_usage(label: &str) {
        epoch::advance().unwrap(); // refresh internal stats!
        let allocated = stats::allocated::read().unwrap();
        println!("[{label}] Heap allocated: {} kilobytes", allocated/1024);
    }

    /// Test creating and getting `LazyCache` values
    #[test]
    fn test_lazy_cache() {
        // get
        {
            // Cached variant
            let cache = LazyCache::preinit(100);
            assert_eq!(*cache.get(), 100);

            // Lazy variant
            let lazy = LazyCache::new(|| {
                let a = 10;
                let b = 20;
                a + b
            });
            assert_eq!(*lazy.get(), 30);
            // Ensure the value is cached and can be accessed multiple times
            assert_eq!(*lazy.get(), 30);
        }

        // function called only once
        {
            let counter = Arc::new(Mutex::new(0));
            let counter_clone = Arc::clone(&counter);

            let cache = LazyCache::new(move || {
                let mut count = counter_clone.lock().unwrap();
                *count += 1;
                // counter_clone will be dropped here
                99
            });

            assert_eq!(*cache.get(), 99);
            assert_eq!(*cache.get(), 99); // Ensure cached
            assert_eq!(*counter.lock().unwrap(), 1); // Function was called exactly once
        }
        // serde
        {
            let cache = LazyCache::preinit(10);
            let serialized = serde_json::to_string(&cache).unwrap();
            let deserialized: LazyCache<i32> = serde_json::from_str(&serialized).unwrap();
            assert_eq!(*deserialized.get(), 10);
        }
        // debug
        {
            let cache = LazyCache::preinit(10);
            assert_eq!(format!("{:?}", cache), "LazyCache(10)");

            let lazy = LazyCache::new(|| 20);
            assert_eq!(format!("{:?}", lazy), "LazyCache(<uninitialized>)");
        }
        // LazyCacheError::MissingFunctionOrInitializedTwice
        {
            let cache: LazyCache<i32> = LazyCache {
                once: Once::new(),
                value: UnsafeCell::new(None),
                init: UnsafeCell::new(None), // No function set
            };
            let err = cache.try_get();
            assert_eq!(
                err.unwrap_err(),
                LazyCacheError::MissingFunctionOrInitializedTwice
            );
        }
        // LazyCacheError::LockPoisoned
        {
            let lazy = Arc::new(LazyCache::<()>::new(|| {
                panic!("poison the lock");
            }));

            let lazy_clone = Arc::clone(&lazy);
            let _ = thread::spawn(move || {
                let _ = lazy_clone.try_initialize();
            })
            .join(); // triggers panic inside init

            // Now the Once is poisoned
            let result = lazy.try_initialize();
            assert_eq!(result, Err(LazyCacheError::LockPoisoned));
        }
    }

    #[test]
    fn test_lazy_cache_allocation() {
        #[global_allocator]
        static GLOBAL: Jemalloc = Jemalloc;

        print_heap_usage("Start");

        let cache = Arc::new(LazyCache::new(|| vec![42u8; 1024 * 1024])); // 1MB

        print_heap_usage("Before initializing LazyCache");

        let _ = cache.get();

        print_heap_usage("After initializing LazyCache");
    }
}
