#![allow(unsafe_code)]

use std::{
    cmp::Eq,
    collections::{hash_map::Entry, HashMap},
    hash::Hash,
    sync::{Arc, Mutex},
};

#[derive(Debug, Clone, Default)]
pub struct HashMapCache<Key: Hash, Value> {
    contents: Arc<Mutex<HashMap<Key, Value>>>,
}

impl<Key: Hash + Eq, Value> HashMapCache<Key, Value> {
    #[must_use]
    pub fn new() -> Self {
        Self {
            contents: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    #[must_use]
    pub fn new_from_hashmap(hashmap: HashMap<Key, Value>) -> Self {
        Self {
            contents: Arc::new(Mutex::new(hashmap)),
        }
    }

    /// Retrieves a cached value by key, or generates and caches it using the
    /// provided closure.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    pub fn get_or_generate<F: FnOnce() -> Value>(&self, key: Key, generator: F) -> &Value {
        let mut hashmap = self.contents.lock().unwrap();
        let entry = (*hashmap).entry(key);
        let inner_ptr = match entry {
            Entry::Occupied(o) => {
                let o_ref = o.into_mut();
                std::ptr::from_ref(o_ref)
            }
            Entry::Vacant(v) => {
                let v_ref = v.insert(generator());
                std::ptr::from_ref(v_ref)
            }
        };
        drop(hashmap);

        // This is safe because we never delete entries from the cache, and the
        // value reference must live at least at most as long as the cache
        // value.
        unsafe { &*inner_ptr }
    }

    /// Returns `true` if the cache contains the given key.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    pub fn contains_key(&self, key: &Key) -> bool {
        self.contents.lock().unwrap().contains_key(key)
    }
}

#[allow(clippy::implicit_hasher)]
#[allow(clippy::fallible_impl_from)]
impl<Key: Hash + Eq + Clone, Value: Clone> From<HashMapCache<Key, Value>> for HashMap<Key, Value> {
    fn from(cache: HashMapCache<Key, Value>) -> Self {
        cache.contents.lock().unwrap().clone()
    }
}
