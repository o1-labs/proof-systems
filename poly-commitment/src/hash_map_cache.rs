use std::{
    collections::{hash_map::Entry, HashMap},
    hash::Hash,
    sync::{Arc, Mutex},
};

#[derive(Debug, Clone, Default)]
pub struct HashMapCache<Key: Hash, Value> {
    contents: Arc<Mutex<HashMap<Key, Value>>>,
}

impl<Key: Hash + std::cmp::Eq, Value> HashMapCache<Key, Value> {
    pub fn new() -> Self {
        HashMapCache {
            contents: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn get_or_generate<'a, F: FnOnce() -> Value>(
        &'a self,
        key: Key,
        generator: F,
    ) -> &'a Value {
        let mut hashmap = self.contents.lock().unwrap();
        let entry = (*hashmap).entry(key);
        let inner_ptr = match entry {
            Entry::Occupied(o) => {
                let o_ref = o.into_mut();
                &*o_ref as *const Value
            }
            Entry::Vacant(v) => {
                let v_ref = v.insert(generator());
                &*v_ref as *const Value
            }
        };

        // This is safe because we never delete entries from the cache, and the value reference
        // must live at least at most as long as the cache value.
        unsafe { &*inner_ptr }
    }

    pub fn contains_key(&self, key: &Key) -> bool {
        self.contents.lock().unwrap().contains_key(key)
    }
}
