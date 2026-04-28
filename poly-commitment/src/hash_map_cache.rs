use std::{
    cmp::Eq,
    collections::HashMap,
    hash::Hash,
    ops::Deref,
    sync::{Arc, Mutex},
};

#[derive(Debug, Clone, Default)]
pub struct HashMapCache<Key: Hash, Value> {
    contents: Arc<Mutex<HashMap<Key, Arc<Value>>>>,
}

impl<Key: Hash + Eq, Value> HashMapCache<Key, Value> {
    #[must_use]
    pub fn new() -> Self {
        Self {
            contents: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    #[must_use]
    pub(crate) fn new_from_hashmap(hashmap: HashMap<Key, Arc<Value>>) -> Self {
        Self {
            contents: Arc::new(Mutex::new(hashmap)),
        }
    }

    /// Sets a value by key only if it hasn't already been set
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    pub fn set_once(&self, key: Key, value: Value) {
        let mut hashmap = self.contents.lock().unwrap();
        let _ = hashmap.entry(key).or_insert_with(|| Arc::new(value));
    }

    /// Retrieves a cached value by key, or generates and caches it using the
    /// provided closure.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    #[allow(clippy::significant_drop_tightening)] // it's a false positive, you can't drop the lock any earlier
    pub(crate) fn get_or_generate<F: FnOnce() -> Value>(
        &self,
        key: Key,
        generator: F,
    ) -> impl Deref<Target = Value> + '_ {
        let mut hashmap = self.contents.lock().unwrap();
        let entry = hashmap.entry(key).or_insert_with(|| Arc::new(generator()));
        Arc::clone(entry)
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
impl<Key: Hash + Eq + Clone, Value: Clone> From<HashMapCache<Key, Value>>
    for HashMap<Key, Arc<Value>>
{
    fn from(cache: HashMapCache<Key, Value>) -> Self {
        cache.contents.lock().unwrap().clone()
    }
}
