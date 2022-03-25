use criterion::{criterion_group, criterion_main, Criterion};
use lockfree_object_pool::SpinLockObjectPool;
use mina_curves::pasta::Fp;
use mina_hasher::{Hashable, Hasher, PoseidonHasherKimchi, PoseidonHasherLegacy, ROInput};
use o1_utils::FieldHelpers;
use serde::Deserialize;
use std::fs::File;
use std::path::PathBuf;

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

#[derive(Debug, Deserialize)]
struct TestVectors {
    test_vectors: Vec<TestVector>,
}

#[derive(Clone, Debug, Deserialize)]
struct TestVector {
    input: Vec<String>,
    output: String,
}

impl Hashable for TestVector {
    type D = ();

    fn to_roinput(&self) -> ROInput {
        let mut roi = ROInput::new();
        // For hashing we only care about the input part
        for input in &self.input {
            roi.append_field(Fp::from_hex(input).expect("failed to deserialize field element"))
        }
        roi
    }

    fn domain_string(_: Option<&Self>, _: Self::D) -> Option<String> {
        None
    }
}

fn test_vectors(test_vector_file: &str, hasher: &mut dyn Hasher<TestVector>) {
    // read test vectors from given file
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("../oracle/tests/test_vectors");
    path.push(&test_vector_file);

    let file = File::open(&path).expect("couldn't open test vector file");
    let test_vectors: TestVectors =
        serde_json::from_reader(file).expect("couldn't deserialize test vector file");

    // execute test vectors
    for test_vector in test_vectors.test_vectors {
        let expected_output =
            Fp::from_hex(&test_vector.output).expect("failed to deserialize field element");

        // hash & check against expect output
        let output = hasher.hash(&test_vector);
        assert_eq!(output, expected_output);
    }
}

fn legacy(c: &mut Criterion) {
    c.bench_function("legacy hasher without pooling", |b| {
        b.iter(|| {
            let mut hasher = mina_hasher::create_legacy::<TestVector>(());
            test_vectors("legacy.json", &mut hasher);
        })
    });
    c.bench_function("legacy hasher with pooling", |b| {
        b.iter(|| {
            let mut hasher = LEGACY_HASHER_POOL.pull();
            test_vectors("legacy.json", &mut *hasher);
        })
    });
}

fn kimchi(c: &mut Criterion) {
    c.bench_function("kimchi hasher without pooling", |b| {
        b.iter(|| {
            let mut hasher = mina_hasher::create_kimchi::<TestVector>(());
            test_vectors("kimchi.json", &mut hasher);
        })
    });
    c.bench_function("kimchi hasher with pooling", |b| {
        b.iter(|| {
            let mut hasher = KIMCHI_HASHER_POOL.pull();
            test_vectors("kimchi.json", &mut *hasher);
        })
    });
}

criterion_group!(benches, legacy, kimchi);
criterion_main!(benches);
