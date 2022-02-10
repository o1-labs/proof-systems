use super::Mode;
use ark_ff::{fields::PrimeField as _, UniformRand as _};
use ark_serialize::CanonicalSerialize as _;
use mina_curves::pasta::Fp;
use num_bigint::BigUint;
use oracle::poseidon::ArithmeticSponge as Poseidon;
use oracle::poseidon::Sponge as _;
use rand::prelude::*;
use rand::Rng;
use serde::Serialize;

//
// generate different test vectors depending on features
//

#[cfg(feature = "3w")]
use oracle::{pasta::fp as Parameters, poseidon::PlonkSpongeConstantsBasic};

#[cfg(feature = "5w")]
use oracle::{pasta::fp5 as Parameters, poseidon::PlonkSpongeConstants5W as PlonkSpongeConstants};

#[cfg(feature = "3")]
use oracle::{pasta::fp_3 as Parameters, poseidon::PlonkSpongeConstants3W as PlonkSpongeConstants};

//
// structs
//

#[derive(Debug, Serialize)]
pub struct TestVectors {
    name: String,
    test_vectors: Vec<TestVector>,
}

#[derive(Debug, Serialize)]
pub struct TestVector {
    input: Vec<String>,
    output: String,
}

//
// logic
//

/// calls the poseidon hash function with the `input` and returns a digest
fn poseidon(input: &[Fp]) -> Fp {
    let mut s = Poseidon::<Fp, PlonkSpongeConstantsBasic>::new(Parameters::params());
    s.absorb(input);

    s.squeeze()
}

/// generates a vector of `length` field elements
fn rand_fields(rng: &mut impl Rng, length: u8) -> Vec<Fp> {
    let mut fields = vec![];
    for _ in 0..length {
        let fe = Fp::rand(rng);
        fields.push(fe)
    }
    fields
}

/// creates a set of test vectors
pub fn generate(mode: Mode) -> TestVectors {
    let mut rng = &mut rand::rngs::StdRng::from_seed([0u8; 32]);
    let mut test_vectors = vec![];

    // generate inputs of different lengths
    for length in 0..6 {
        // generate input & hash
        let input = rand_fields(&mut rng, length);
        let output = poseidon(&input);

        // serialize input & output
        let input = input
            .into_iter()
            .map(|elem| {
                let mut input_bytes = vec![];
                elem.into_repr()
                    .serialize(&mut input_bytes)
                    .expect("canonical serialiation should work");
                match mode {
                    Mode::Hex => hex::encode(&input_bytes),
                    Mode::B10 => BigUint::from_bytes_le(&input_bytes).to_string(),
                }
            })
            .collect();
        let mut output_bytes = vec![];
        output
            .into_repr()
            .serialize(&mut output_bytes)
            .expect("canonical serialization should work");

        // add vector
        test_vectors.push(TestVector {
            input,
            output: hex::encode(&output_bytes),
        })
    }

    let name = if cfg!(feature = "3w") {
        "3w".to_string()
    } else if cfg!(feature = "3") {
        "3".to_string()
    } else if cfg!(feature = "5w") {
        "5w".to_string()
    } else {
        panic!("test vector feature not recognized");
    };

    //
    TestVectors { name, test_vectors }
}
