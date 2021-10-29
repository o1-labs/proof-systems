use ark_ff::{BigInteger256, PrimeField};
use ark_serialize::CanonicalDeserialize as _;
use mina_curves::pasta::Fp;
use oracle::poseidon::Sponge as _;
use serde::Deserialize;
use std::fs::File;
use std::path::PathBuf; // needed for ::new() sponge

use oracle::poseidon::ArithmeticSponge as Poseidon;

use oracle::pasta::fp as Parameters3W;
use oracle::poseidon::PlonkSpongeConstantsBasic;

use oracle::pasta::fp5 as Parameters5W;
use oracle::poseidon::PlonkSpongeConstants5W;

use oracle::pasta::fp_3 as Parameters3;
use oracle::poseidon::PlonkSpongeConstants3W;

//
// Helpers for test vectors
//

#[derive(Debug, Deserialize)]
struct TestVectors {
    name: String,
    test_vectors: Vec<TestVector>,
}

#[derive(Debug, Deserialize)]
struct TestVector {
    input: Vec<String>,
    output: String,
}

fn hex_to_field(hexstring: &str) -> Fp {
    let bytearray = hex::decode(hexstring).expect("couldn't deserialize hex encoded test vector");
    let bignum = BigInteger256::deserialize(&mut &bytearray[..])
        .expect("couldn't deserialize bignum representation");
    Fp::from_repr(bignum).unwrap()
}

fn test_vectors<F>(test_vector_file: &str, hash: F)
where
    F: Fn(&[Fp]) -> Fp,
{
    // read test vectors from given file
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("tests/test_vectors");
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
            .map(|hexstring| hex_to_field(&hexstring))
            .collect();
        let expected_output = hex_to_field(&test_vector.output);

        // hash & check against expect output
        let output = hash(&input);
        assert_eq!(output, expected_output);
    }
}

//
// Tests
//

#[test]
fn poseidon_test_vectors_3w() {
    fn hash(input: &[Fp]) -> Fp {
        let mut hash = Poseidon::<Fp, PlonkSpongeConstantsBasic>::new(Parameters3W::params());
        hash.absorb(input);
        hash.squeeze()
    }
    test_vectors("3w.json", hash);
}

#[test]
fn poseidon_test_vectors_5w() {
    fn hash(input: &[Fp]) -> Fp {
        let mut hash = Poseidon::<Fp, PlonkSpongeConstants5W>::new(Parameters5W::params());
        hash.absorb(input);
        hash.squeeze()
    }
    test_vectors("5w.json", hash);
}

#[test]
fn poseidon_test_vectors_3() {
    fn hash(input: &[Fp]) -> Fp {
        let mut hash = Poseidon::<Fp, PlonkSpongeConstants3W>::new(Parameters3::params());
        hash.absorb(input);
        hash.squeeze()
    }
    test_vectors("3.json", hash);
}
