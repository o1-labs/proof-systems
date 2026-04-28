//! A `no_std`-compatible replacement for [`std::sync::LazyLock`].
//!
//! When the `std` feature is enabled, this delegates directly to
//! [`std::sync::LazyLock`]. In `no_std` mode, this delegates to
//! [`spin::Lazy`] which uses a spin-based `Once` internally.

use core::ops::Deref;

/// A thread-safe, lazily-initialized value.
///
/// Constructed with a function (typically `fn() -> T`) so that it can be used
/// in `static` items via [`LazyLock::new`], which is `const`.
///
/// # Examples
///
/// ```
/// use o1_utils::lazy_lock::LazyLock;
///
/// static VALUE: LazyLock<u64> = LazyLock::new(|| 1 + 2);
///
/// assert_eq!(*VALUE, 3);
/// ```
#[cfg(feature = "std")]
pub struct LazyLock<T, F = fn() -> T> {
    inner: std::sync::LazyLock<T, F>,
}

#[cfg(feature = "std")]
impl<T, F: FnOnce() -> T> LazyLock<T, F> {
    pub const fn new(init: F) -> Self {
        Self {
            inner: std::sync::LazyLock::new(init),
        }
    }
}

#[cfg(feature = "std")]
impl<T, F: FnOnce() -> T> Deref for LazyLock<T, F> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.inner
    }
}

/// A thread-safe, lazily-initialized value (no-std fallback via [`spin::Lazy`]).
#[cfg(not(feature = "std"))]
pub struct LazyLock<T, F = fn() -> T> {
    inner: spin::Lazy<T, F>,
}

#[cfg(not(feature = "std"))]
impl<T, F: FnOnce() -> T> LazyLock<T, F> {
    pub const fn new(init: F) -> Self {
        Self {
            inner: spin::Lazy::new(init),
        }
    }
}

#[cfg(not(feature = "std"))]
impl<T, F: FnOnce() -> T> Deref for LazyLock<T, F> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.inner
    }
}

#[cfg(test)]
mod tests {
    use super::LazyLock;
    extern crate std;

    #[test]
    fn lazy_lock_panic() {
        static VALUE: LazyLock<u64> = LazyLock::new(|| {
            panic!("test_lazy_lock_panic");
        });

        std::thread::scope(|s| {
            let error_counts = (0..4)
                .map(|_| {
                    s.spawn(|| {
                        assert_eq!(*VALUE, 3);
                    })
                })
                .map(|thread| thread.join().unwrap_err())
                .map(|err| *err.downcast_ref::<&'static str>().unwrap())
                .fold(std::collections::HashMap::new(), |mut acc, err| {
                    *acc.entry(err).or_insert(0) += 1;
                    acc
                });

            #[cfg(feature = "std")]
            let poisoned_msg = "LazyLock instance has previously been poisoned";
            #[cfg(not(feature = "std"))]
            let poisoned_msg = "Once panicked";

            assert_eq!(error_counts.get("test_lazy_lock_panic").copied(), Some(1));
            assert_eq!(
                error_counts.get(poisoned_msg).copied(),
                Some(3),
                "missing poisoned errors, use `std::dbg!` to see all errors"
            );
        });
    }

    #[test]
    fn lazy_lock_success() {
        static VALUE: LazyLock<u64> = LazyLock::new(|| 3);

        std::thread::scope(|s| {
            let threads = (0..4)
                .map(|_| {
                    s.spawn(|| {
                        assert_eq!(*VALUE, 3);
                    })
                })
                .collect::<alloc::vec::Vec<_>>();

            for thread in threads {
                thread.join().unwrap();
            }

            assert_eq!(*VALUE, 3);
        });
    }
}
