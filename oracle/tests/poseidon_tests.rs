use serde::Deserialize;
use std::fs::File;
use std::path::PathBuf;

use algebra::{
    fields::PrimeField, pasta::Fp, BigInteger256, CanonicalDeserialize as _, UniformRand,
};
use oracle::poseidon::Sponge as _; // needed for ::new() sponge

use oracle::poseidon::ArithmeticSponge as Poseidon;

use oracle::pasta::fp as Parameters;
use oracle::poseidon::PlonkSpongeConstants;

use oracle::pasta::fp5 as Parameters5W;
use oracle::poseidon::PlonkSpongeConstants5W;

use oracle::pasta::fp_3 as Parameters3;
use oracle::poseidon::PlonkSpongeConstants3;

//
// Helpers for test vectors
//

#[derive(Debug, Deserialize)]
pub struct TestVector {
    input: Vec<String>,
    output: String,
}

fn hex_to_field(hexstring: &str) -> Fp {
    let bytearray = hex::decode(hexstring).expect("couldn't deserialize hex encoded test vector");
    let bignum = BigInteger256::deserialize(&mut &bytearray[..])
        .expect("couldn't deserialize bignum representation");
    Fp::from_repr(bignum)
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
    let test_vectors: Vec<TestVector> =
        serde_json::from_reader(file).expect("couldn't deserialize test vector file");

    // execute test vectors
    for test_vector in test_vectors {
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
fn poseidon_test_vectors_3_wires() {
    fn hash(input: &[Fp]) -> Fp {
        let mut hash = Poseidon::<Fp, PlonkSpongeConstants>::new();
        hash.absorb(&Parameters::params(), input);
        hash.squeeze(&Parameters::params())
    }
    test_vectors("three_wire.json", hash);
}

#[test]
fn poseidon_test_vectors_5_wires() {
    fn hash(input: &[Fp]) -> Fp {
        let mut hash = Poseidon::<Fp, PlonkSpongeConstants5W>::new();
        hash.absorb(&Parameters5W::params(), input);
        hash.squeeze(&Parameters5W::params())
    }
    test_vectors("five_wire.json", hash);
}

#[test]
fn poseidon_test_vectors_fp_3() {
    fn hash(input: &[Fp]) -> Fp {
        let mut hash = Poseidon::<Fp, PlonkSpongeConstants3>::new();
        hash.absorb(&Parameters3::params(), input);
        hash.squeeze(&Parameters3::params())
    }
    test_vectors("fp_3.json", hash);
}
