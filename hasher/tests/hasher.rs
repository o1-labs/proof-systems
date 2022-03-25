use lockfree_object_pool::SpinLockObjectPool;
use mina_curves::pasta::Fp;
use mina_hasher::{Hashable, Hasher, PoseidonHasherLegacy, ROInput};
use o1_utils::FieldHelpers;
use serde::Deserialize;
use std::fs::File;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

lazy_static::lazy_static! {
    static ref LEGACY_HASHER_POOL: LegacyHasherPool = LegacyHasherPool::new();
}

//
// Helpers for test vectors
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

#[test]
fn hasher_pooling_test_vectors_legacy() {
    let mut hasher = LEGACY_HASHER_POOL.pool().pull();
    test_vectors("legacy.json", &mut *hasher);
}

#[test]
fn hasher_pooling_test_vectors_legacy_ensure_pool_size() {
    for _ in 0..128 {
        hasher_pooling_test_vectors_legacy();
        // Use 2 here because `hasher_pooling_test_vectors_legacy` test case may run in parallel
        assert!(LEGACY_HASHER_POOL.n_created() <= 2);
    }
}
