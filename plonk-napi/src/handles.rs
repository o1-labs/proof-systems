use std::{
    convert::TryFrom,
    sync::{Mutex, MutexGuard, OnceLock},
};

/// Public type alias for the opaque handle we expose to JS.
/// Using u32 keeps it JS-friendly (fits into a 32-bit integer safely).
pub type Handle = u32;

/// A simple slot store with O(1) insert/get/remove and reuses indices to avoid
/// unbounded growth.
#[derive(Debug)]
pub struct HandleStore<T> {
    /// Slots of store, can be free if `None`, or in use if `Some(T)`
    entries: Vec<Option<T>>,
    /// Indices of reusable empty slots
    free: Vec<Handle>,
}

impl<T> HandleStore<T> {
    /// Create an empty store.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            free: Vec::new(),
        }
    }

    /// Insert a new value and return its handle.
    /// Reuses a previously freed slot if available; otherwise pushes to the end.
    pub fn insert(&mut self, value: T) -> Handle {
        if let Some(handle) = self.free.pop() {
            self.entries[handle as usize] = Some(value);
            handle
        } else {
            let index = self.entries.len();
            let handle = Handle::try_from(index).expect("handle counter overflow");
            self.entries.push(Some(value));
            handle
        }
    }

    /// Borrow an immutable reference for a given handle.
    /// Returns None if the handle is out of range or currently free.
    pub fn get(&self, handle: Handle) -> Option<&T> {
        self.entries.get(handle as usize)?.as_ref()
    }

    /// Borrow a mutable reference for a given handle.
    pub fn get_mut(&mut self, handle: Handle) -> Option<&mut T> {
        self.entries.get_mut(handle as usize)?.as_mut()
    }

    /// Remove and return the value for a given handle, marking the slot free
    /// and enqueuing it for reuse.
    pub fn remove(&mut self, handle: Handle) -> Option<T> {
        let slot = self.entries.get_mut(handle as usize)?;
        let value = slot.take()?;
        self.free.push(handle);
        Some(value)
    }

    /// Returns whether this handle currently points to a live value
    pub fn contains(&self, handle: Handle) -> bool {
        self.entries
            .get(handle as usize)
            .map_or(false, |entry| entry.is_some())
    }

    /// Number of live values (occupied slots). Note this is not `entries.len()`.
    pub fn len(&self) -> usize {
        self.entries.len() - self.free.len()
    }

    /// Whether the store is empty (no entries at all)
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// A process-global store with lazy initialization and interior locking.
/// - `OnceLock` ensures we only create the Mutex once.
/// - `Mutex<HandleStore<T>>` gives exclusive access to the underlying store.
pub struct GlobalHandleStore<T> {
    inner: OnceLock<Mutex<HandleStore<T>>>,
}

impl<T> GlobalHandleStore<T> {
    /// Const constructor so you can declare as static store
    pub const fn new() -> Self {
        Self {
            inner: OnceLock::new(),
        }
    }

    /// Get a locked guard to the store, initializing it on first use.
    /// Panics only if the mutex is poisoned (previous panic while holding the lock).
    pub fn lock(&self) -> MutexGuard<'_, HandleStore<T>> {
        self.inner
            .get_or_init(|| Mutex::new(HandleStore::new()))
            .lock()
            .expect("handle store poisoned")
    }
}
