use crate::{
    constants::{PlonkSpongeConstantsKimchi, PlonkSpongeConstantsLegacy},
    pasta::*,
    poseidon::ArithmeticSponge as Poseidon,
    poseidon::Sponge as _,
};
use mina_curves::pasta::Fp;
use o1_utils::FieldHelpers;
use serde::Deserialize;
use std::fs::File;
use std::path::PathBuf; // needed for ::new() sponge

//
// Helpers for test vectors
//

#[derive(Debug, Deserialize)]
struct TestVectors {
    test_vectors: Vec<TestVector>,
}

#[derive(Debug, Deserialize)]
struct TestVector {
    input: Vec<String>,
    output: String,
}

fn test_vectors<F>(test_vector_file: &str, hash: F)
where
    F: Fn(&[Fp]) -> Fp,
{
    // read test vectors from given file
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("src/tests/test_vectors");
    path.push(&test_vector_file);
    let file = File::open(&path).expect("couldn't open test vector file");
    let test_vectors: TestVectors =
        serde_json::from_reader(file).expect("couldn't deserialize test vector file");

    // execute test vectors
    for test_vector in test_vectors.test_vectors {
        // deserialize input & ouptut
        let input: Vec<Fp> = test_vector
            .input
            .into_iter()
            .map(|hexstring| Fp::from_hex(&hexstring).expect("failed to deserialize field element"))
            .collect();
        let expected_output =
            Fp::from_hex(&test_vector.output).expect("failed to deserialize field element");

        // hash & check against expect output
        assert_eq!(hash(&input), expected_output);
    }
}

//
// Tests
//

#[test]
fn poseidon_test_vectors_legacy() {
    fn hash(input: &[Fp]) -> Fp {
        let mut hash = Poseidon::<Fp, PlonkSpongeConstantsLegacy>::new(fp_legacy_params());
        hash.absorb(input);
        hash.squeeze()
    }
    test_vectors("legacy.json", hash);
}

#[test]
fn poseidon_test_vectors_kimchi() {
    fn hash(input: &[Fp]) -> Fp {
        let mut hash = Poseidon::<Fp, PlonkSpongeConstantsKimchi>::new(fp_kimchi_params());
        hash.absorb(input);
        hash.squeeze()
    }
    test_vectors("kimchi.json", hash);
}
