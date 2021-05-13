use oracle::poseidon::Sponge as _;
use rand::prelude::*;
use rand::Rng;
use serde::Serialize;

//
// generate different test vectors depending on features
//

use algebra::{fields::PrimeField as _, pasta::Fp, CanonicalSerialize as _, UniformRand as _};

use oracle::poseidon::ArithmeticSponge as Poseidon;

#[cfg(feature = "three_wire")]
use oracle::{pasta::fp as Parameters, poseidon::PlonkSpongeConstants};

#[cfg(feature = "fp_3")]
use oracle::{pasta::fp_3 as Parameters, poseidon::PlonkSpongeConstants3 as PlonkSpongeConstants};

#[cfg(feature = "five_wire")]
use oracle::{pasta::fp5 as Parameters, poseidon::PlonkSpongeConstants5W as PlonkSpongeConstants};

//
// structs
//

#[derive(Debug, Serialize)]
pub struct TestVector {
    input: Vec<String>,
    output: String,
}

//
// logic
//

// calls the poseidon hash function with the `input` and returns a digest
fn poseidon(input: &[Fp]) -> Fp {
    let mut s = Poseidon::<Fp, PlonkSpongeConstants>::new();
    s.absorb(&Parameters::params(), input);
    let output = s.squeeze(&Parameters::params());
    output
}

// generates a vector of `length` field elements
fn rand_fields(rng: &mut impl Rng, length: u8) -> Vec<Fp> {
    let mut fields = vec![];
    for _ in 0..length {
        let fe = Fp::rand(rng);
        fields.push(fe)
    }
    fields
}

// creates a set of test vectors
pub fn generate() -> Vec<TestVector> {
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
                hex::encode(&input_bytes)
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

    //
    test_vectors
}
