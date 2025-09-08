use ark_ec::AffineRepr;
use ark_ff::{Field, UniformRand};
use mina_curves::pasta::{Fp, Fq, Pallas, PallasParameters, Vesta, VestaParameters};
use mina_poseidon::{
    constants::{PlonkSpongeConstantsKimchi, PlonkSpongeConstantsLegacy},
    pasta::{fp_kimchi, fp_legacy, fq_kimchi},
    poseidon::{ArithmeticSponge as Poseidon, Sponge as _},
    sponge::DefaultFqSponge,
    FqSponge as _,
};
use o1_utils::FieldHelpers;
use rand::Rng;
use serde::Deserialize;
use std::{fs::File, path::PathBuf}; // needed for ::new() sponge

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
    path.push("tests/test_vectors");
    path.push(test_vector_file);
    let file = File::open(&path).expect("couldn't open test vector file");
    let test_vectors: TestVectors =
        serde_json::from_reader(file).expect("couldn't deserialize test vector file");

    // execute test vectors
    for test_vector in test_vectors.test_vectors {
        // deserialize input & output
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
        let mut hash = Poseidon::<Fp, PlonkSpongeConstantsLegacy>::new(fp_legacy::static_params());
        hash.absorb(input);
        hash.squeeze()
    }
    test_vectors("legacy.json", hash);
}

#[test]
fn poseidon_test_vectors_kimchi() {
    fn hash(input: &[Fp]) -> Fp {
        let mut hash = Poseidon::<Fp, PlonkSpongeConstantsKimchi>::new(fp_kimchi::static_params());
        hash.absorb(input);
        hash.squeeze()
    }
    test_vectors("kimchi.json", hash);
}

#[test]
fn test_regression_challenge_empty_vesta_kimchi() {
    let mut sponge = DefaultFqSponge::<VestaParameters, PlonkSpongeConstantsKimchi>::new(
        fq_kimchi::static_params(),
    );
    let output = sponge.challenge();
    let exp_output =
        Fp::from_hex("c1e504c0184cce70a605d2f942d579c500000000000000000000000000000000").unwrap();
    assert_eq!(output, exp_output);
}

#[test]
fn test_regression_challenge_empty_pallas_kimchi() {
    let mut sponge = DefaultFqSponge::<PallasParameters, PlonkSpongeConstantsKimchi>::new(
        fp_kimchi::static_params(),
    );
    let output = sponge.challenge();
    let exp_output =
        Fq::from_hex("a8eb9ee0f30046308abbfa5d20af73c800000000000000000000000000000000").unwrap();
    assert_eq!(output, exp_output);
}

#[test]
fn test_poseidon_vesta_kimchi_challenge_is_squeezed_to_128_bits() {
    // Test that the challenge is less than 2^128, i.e. the sponge state is
    // squeezed to 128 bits
    let mut sponge = DefaultFqSponge::<VestaParameters, PlonkSpongeConstantsKimchi>::new(
        fq_kimchi::static_params(),
    );
    let mut rng = o1_utils::tests::make_test_rng(None);
    let random_n = rng.gen_range(1..50);
    let random_fq_vec = (0..random_n)
        .map(|_| Fq::rand(&mut rng))
        .collect::<Vec<Fq>>();
    sponge.absorb_fq(&random_fq_vec);
    let challenge = sponge.challenge();
    let two_128 = Fp::from(2).pow([128]);
    assert!(challenge < two_128);
}

#[test]
fn test_poseidon_pallas_kimchi_challenge_is_squeezed_to_128_bits() {
    // Test that the challenge is less than 2^128, i.e. the sponge state is
    // squeezed to 128 bits
    let mut sponge = DefaultFqSponge::<PallasParameters, PlonkSpongeConstantsKimchi>::new(
        fp_kimchi::static_params(),
    );
    let mut rng = o1_utils::tests::make_test_rng(None);
    let random_n = rng.gen_range(1..50);
    let random_fp_vec = (0..random_n)
        .map(|_| Fp::rand(&mut rng))
        .collect::<Vec<Fp>>();
    sponge.absorb_fq(&random_fp_vec);
    let challenge = sponge.challenge();
    let two_128 = Fq::from(2).pow([128]);
    assert!(challenge < two_128);
}

#[test]
fn test_poseidon_pallas_absorb_point_to_infinity() {
    let mut sponge = DefaultFqSponge::<PallasParameters, PlonkSpongeConstantsKimchi>::new(
        fp_kimchi::static_params(),
    );
    let point = Pallas::zero();
    sponge.absorb_g(&[point]);
    let exp_output = [Fp::from(0); 3];
    assert_eq!(sponge.sponge.state, exp_output);
}

#[test]
fn test_poseidon_vesta_absorb_point_to_infinity() {
    let mut sponge = DefaultFqSponge::<VestaParameters, PlonkSpongeConstantsKimchi>::new(
        fq_kimchi::static_params(),
    );
    let point = Vesta::zero();
    sponge.absorb_g(&[point]);
    let exp_output = [Fq::from(0); 3];
    assert_eq!(sponge.sponge.state, exp_output);
}

#[test]
fn test_poseidon_challenge_multiple_times_without_absorption() {
    let mut sponge = DefaultFqSponge::<VestaParameters, PlonkSpongeConstantsKimchi>::new(
        fq_kimchi::static_params(),
    );
    let mut rng = o1_utils::tests::make_test_rng(None);
    let random_n = rng.gen_range(10..50);

    let mut old_state = sponge.sponge.state.clone();
    let mut new_state = sponge.sponge.state.clone();
    // Only to avoid a warning. old_state must be used.
    assert_eq!(
        old_state, new_state,
        "States must be the same after initialization"
    );
    let mut challenges: Vec<_> = vec![];

    for i in 0..random_n {
        old_state.clone_from(&new_state);
        new_state.clone_from(&sponge.sponge.state);
        let chal = sponge.challenge();
        if i % 2 == 0 {
            assert_eq!(
                old_state, new_state,
                "States must be the same after squeezing an even number of times"
            );
        } else {
            assert_ne!(
                old_state, new_state,
                "States must not be the same after squeezing an odd number of times"
            );
        }
        assert!(
            !challenges.contains(&chal),
            "Challenges must always be different, even without any absorption"
        );
        challenges.push(chal);
    }
}
