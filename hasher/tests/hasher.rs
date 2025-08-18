use mina_hasher::{create_kimchi, create_legacy, Fp, Hashable, Hasher, ROInput};
use o1_utils::FieldHelpers;
use serde::Deserialize;
use std::{fs::File, path::PathBuf};

//
// Helpers for test vectors
//

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
            roi =
                roi.append_field(Fp::from_hex(input).expect("failed to deserialize field element"));
        }
        roi
    }

    fn domain_string(_: Self::D) -> Option<String> {
        None
    }
}

fn test_vectors(test_vector_file: &str, hasher: &mut dyn Hasher<TestVector>) {
    // read test vectors from given file
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("../poseidon/tests/test_vectors");
    path.push(test_vector_file);

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
    let mut hasher = create_legacy::<TestVector>(());
    test_vectors("legacy.json", &mut hasher);
}

#[test]
fn hasher_test_vectors_kimchi() {
    let mut hasher = create_kimchi::<TestVector>(());
    test_vectors("kimchi.json", &mut hasher);
}

#[test]
fn interfaces() {
    #[derive(Clone)]
    struct Foo {
        x: u32,
        y: u64,
    }

    impl Hashable for Foo {
        type D = u64;

        fn to_roinput(&self) -> ROInput {
            ROInput::new().append_u32(self.x).append_u64(self.y)
        }

        fn domain_string(id: u64) -> Option<String> {
            format!("Foo {id}").into()
        }
    }

    // Usage 1: incremental interface
    let mut hasher = create_legacy::<Foo>(0);
    hasher.update(&Foo { x: 3, y: 1 });
    // Resets to previous init state (0)
    let x1 = hasher.digest();
    hasher.update(&Foo { x: 82, y: 834 });
    hasher.update(&Foo { x: 1235, y: 93 });
    // Resets to previous init state (0)
    hasher.digest();
    hasher.init(1);
    hasher.update(&Foo { x: 82, y: 834 });
    // Resets to previous init state (1)
    let x2 = hasher.digest();

    // Usage 2: builder interface with one-shot pattern
    let mut hasher = create_legacy::<Foo>(0);
    // Resets to previous init state (0)
    let y1 = hasher.update(&Foo { x: 3, y: 1 }).digest();

    hasher.update(&Foo { x: 31, y: 21 }).digest();

    // Usage 3: builder interface with one-shot pattern also setting init state
    let mut hasher = create_legacy::<Foo>(0);
    // Resets to previous init state (1)
    let y2 = hasher.init(0).update(&Foo { x: 3, y: 1 }).digest();
    // Resets to previous init state (2)
    let y3 = hasher.init(1).update(&Foo { x: 82, y: 834 }).digest();

    // Usage 4: one-shot interfaces
    let mut hasher = create_legacy::<Foo>(0);
    let y4 = hasher.hash(&Foo { x: 3, y: 1 });
    let y5 = hasher.init_and_hash(1, &Foo { x: 82, y: 834 });

    assert_eq!(x1, y1);
    assert_eq!(x1, y2);
    assert_eq!(x2, y3);
    assert_eq!(x1, y4);
    assert_eq!(x2, y5);
    assert_ne!(x1, y5);
    assert_ne!(x2, y4);
    assert_ne!(x1, y3);
    assert_ne!(x2, y2);
}
