use criterion::{criterion_group, criterion_main, Criterion};
use lockfree_object_pool::SpinLockObjectPool;
use mina_hasher::{Hasher, PoseidonHasherKimchi, PoseidonHasherLegacy};
mod test_vector;
use test_vector::*;

lazy_static::lazy_static! {
    static ref LEGACY_HASHER_POOL: SpinLockObjectPool<PoseidonHasherLegacy<TestVector>> = SpinLockObjectPool::new(
        || mina_hasher::create_legacy::<TestVector>(()),
        |hasher| {
            hasher.reset();
        }
    );
    static ref KIMCHI_HASHER_POOL: SpinLockObjectPool<PoseidonHasherKimchi<TestVector>> = SpinLockObjectPool::new(
        || mina_hasher::create_kimchi::<TestVector>(()),
        |hasher| {
            hasher.reset();
        }
    );
}

fn legacy_no_pooling(c: &mut Criterion) {
    c.bench_function("legacy hasher without pooling", |b| {
        b.iter(|| {
            let mut hasher = mina_hasher::create_legacy::<TestVector>(());
            test_vectors("legacy.json", &mut hasher);
        })
    });
}

fn legacy_pooling(c: &mut Criterion) {
    c.bench_function("legacy hasher with pooling", |b| {
        b.iter(|| {
            let mut hasher = LEGACY_HASHER_POOL.pull();
            test_vectors("legacy.json", &mut *hasher);
        })
    });
}

fn kimchi_no_pooling(c: &mut Criterion) {
    c.bench_function("kimchi hasher without pooling", |b| {
        b.iter(|| {
            let mut hasher = mina_hasher::create_kimchi::<TestVector>(());
            test_vectors("kimchi.json", &mut hasher);
        })
    });
}

fn kimchi_pooling(c: &mut Criterion) {
    c.bench_function("kimchi hasher with pooling", |b| {
        b.iter(|| {
            let mut hasher = KIMCHI_HASHER_POOL.pull();
            test_vectors("kimchi.json", &mut *hasher);
        })
    });
}

criterion_group!(
    benches,
    legacy_no_pooling,
    legacy_pooling,
    kimchi_no_pooling,
    kimchi_pooling
);
criterion_main!(benches);
