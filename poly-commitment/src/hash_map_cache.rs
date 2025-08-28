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
    pub fn new() -> Self {
        HashMapCache {
            contents: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn new_from_hashmap(hashmap: HashMap<Key, Value>) -> Self {
        HashMapCache {
            contents: Arc::new(Mutex::new(hashmap)),
        }
    }

    pub fn get_or_generate<F: FnOnce() -> Value>(&self, key: Key, generator: F) -> &Value {
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

        // This is safe because we never delete entries from the cache, and the
        // value reference must live at least at most as long as the cache
        // value.
        unsafe { &*inner_ptr }
    }

    pub fn contains_key(&self, key: &Key) -> bool {
        self.contents.lock().unwrap().contains_key(key)
    }
}

impl<Key: Hash + Eq + Clone, Value: Clone> From<HashMapCache<Key, Value>> for HashMap<Key, Value> {
    fn from(cache: HashMapCache<Key, Value>) -> HashMap<Key, Value> {
        cache.contents.lock().unwrap().clone()
    }
}
