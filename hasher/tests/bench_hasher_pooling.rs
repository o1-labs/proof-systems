use criterion::{criterion_group, criterion_main, Criterion};
use lockfree_object_pool::SpinLockObjectPool;
use mina_hasher::{Hasher, PoseidonHasherKimchi, PoseidonHasherLegacy};
mod test_vector;
use once_cell::sync::OnceCell;
use test_vector::*;

static LEGACY_HASHER_POOL: OnceCell<SpinLockObjectPool<PoseidonHasherLegacy<TestVector>>> =
    OnceCell::new();
static KIMCHI_HASHER_POOL: OnceCell<SpinLockObjectPool<PoseidonHasherKimchi<TestVector>>> =
    OnceCell::new();

fn pooling(c: &mut Criterion) {
    LEGACY_HASHER_POOL
        .set(SpinLockObjectPool::new(
            || mina_hasher::create_legacy::<TestVector>(()),
            |hasher| {
                hasher.reset();
            },
        ))
        .map_err(|_| "Failed to set legacy hasher pool")
        .unwrap();
    KIMCHI_HASHER_POOL
        .set(SpinLockObjectPool::new(
            || mina_hasher::create_kimchi::<TestVector>(()),
            |hasher| {
                hasher.reset();
            },
        ))
        .map_err(|_| "Failed to set kimchi hasher pool")
        .unwrap();

    c.bench_function("legacy hasher without pooling", |b| {
        b.iter(|| {
            let mut hasher = mina_hasher::create_legacy::<TestVector>(());
            test_vectors("legacy.json", &mut hasher);
        })
    });

    c.bench_function("legacy hasher with pooling", |b| {
        b.iter(|| {
            let mut hasher = LEGACY_HASHER_POOL.get().unwrap().pull();
            test_vectors("legacy.json", &mut *hasher);
        })
    });

    c.bench_function("kimchi hasher without pooling", |b| {
        b.iter(|| {
            let mut hasher = mina_hasher::create_kimchi::<TestVector>(());
            test_vectors("kimchi.json", &mut hasher);
        })
    });

    c.bench_function("kimchi hasher with pooling", |b| {
        b.iter(|| {
            let mut hasher = KIMCHI_HASHER_POOL.get().unwrap().pull();
            test_vectors("kimchi.json", &mut *hasher);
        })
    });
}

criterion_group!(benches, pooling,);
criterion_main!(benches);
