use lockfree_object_pool::SpinLockObjectPool;
use mina_hasher::{Hasher, PoseidonHasherLegacy};
use std::sync::{Arc, RwLock};
mod test_vector;
use test_vector::*;

lazy_static::lazy_static! {
    static ref LEGACY_HASHER_POOL: LegacyHasherPool = LegacyHasherPool::new();
}

//
// Helpers for hasher pooling
//

struct LegacyHasherPool {
    n_created: Arc<RwLock<usize>>,
    pool: SpinLockObjectPool<PoseidonHasherLegacy<TestVector>>,
}

impl LegacyHasherPool {
    pub fn new() -> Self {
        let n_created = Arc::new(RwLock::new(0));
        let n_created_clone = n_created.clone();
        let pool = SpinLockObjectPool::new(
            move || {
                println!("creating hasher");
                let hasher = mina_hasher::create_legacy::<TestVector>(());
                let mut locked = n_created_clone.write().unwrap();
                *locked += 1;
                hasher
            },
            |hasher| {
                hasher.reset();
            },
        );
        Self { n_created, pool }
    }

    pub fn n_created(&self) -> usize {
        *self.n_created.read().unwrap()
    }

    pub fn pool(&self) -> &SpinLockObjectPool<PoseidonHasherLegacy<TestVector>> {
        &self.pool
    }
}

//
// Tests
//

#[test]
fn hasher_test_vectors_legacy() {
    let mut hasher = mina_hasher::create_legacy::<TestVector>(());
    test_vectors("legacy.json", &mut hasher);
}

#[test]
fn hasher_test_vectors_kimchi() {
    let mut hasher = mina_hasher::create_kimchi::<TestVector>(());
    test_vectors("kimchi.json", &mut hasher);
}

// This is mainly to make sure the pooling code compiles
#[test]
fn hasher_pooling_compile_test_vectors_legacy() {
    let mut hasher = LEGACY_HASHER_POOL.pool().pull();
    test_vectors("legacy.json", &mut *hasher);
}

#[test]
fn hasher_pooling_compile_test_vectors_legacy_ensure_pool_size() {
    for _ in 0..128 {
        hasher_pooling_compile_test_vectors_legacy();
        let n_created = LEGACY_HASHER_POOL.n_created();
        // Use 2 here because `hasher_pooling_test_vectors_legacy` test case may run in parallel
        assert!(
            n_created > 0 && n_created <= 2,
            "n_created value {} is out of expected range",
            n_created
        );
    }
}
