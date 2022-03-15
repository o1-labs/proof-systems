use ark_ff::{BigInteger256, PrimeField};
use ark_serialize::CanonicalDeserialize as _;
use mina_curves::pasta::Fp;
use oracle::poseidon::Sponge as _;
use serde::Deserialize;
use std::fs::File;
use std::path::PathBuf; // needed for ::new() sponge

use oracle::poseidon::ArithmeticSponge as Poseidon;

use oracle::constants::PlonkSpongeConstantsKimchi;
use oracle::constants::PlonkSpongeConstantsLegacy;
use oracle::pasta::fp_kimchi as SpongeParametersKimchi;
use oracle::pasta::fp_legacy as SpongeParametersLegacy;

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
fn poseidon_test_vectors_legacy() {
    fn hash(input: &[Fp]) -> Fp {
        let mut hash =
            Poseidon::<Fp, PlonkSpongeConstantsLegacy>::new(SpongeParametersLegacy::params());
        hash.absorb(input);
        hash.squeeze()
    }
    test_vectors("legacy.json", hash);
}

#[test]
fn poseidon_test_vectors_kimchi() {
    fn hash(input: &[Fp]) -> Fp {
        let mut hash =
            Poseidon::<Fp, PlonkSpongeConstantsKimchi>::new(SpongeParametersKimchi::params());
        hash.absorb(input);
        hash.squeeze()
    }
    test_vectors("kimchi.json", hash);
}
