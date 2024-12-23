use super::{Mode, ParamType};
use ark_ff::{PrimeField, UniformRand as _};
use ark_serialize::CanonicalSerialize as _;
use mina_curves::pasta::Fp;
use mina_poseidon::{
    constants::{self, SpongeConstants},
    pasta,
    poseidon::{ArithmeticSponge as Poseidon, ArithmeticSpongeParams, Sponge as _},
};
use num_bigint::BigUint;
use rand::Rng;
use serde::Serialize;

//
// generate different test vectors depending on [ParamType]
//

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

/// Computes the poseidon hash of several field elements.
/// Uses the 'basic' configuration with N states and M rounds.
fn poseidon<SC: SpongeConstants>(input: &[Fp], params: &'static ArithmeticSpongeParams<Fp>) -> Fp {
    let mut s = Poseidon::<Fp, SC>::new(params);
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
pub fn generate(mode: Mode, param_type: ParamType) -> TestVectors {
    let rng = &mut o1_utils::tests::make_test_rng(Some([0u8; 32]));
    let mut test_vectors = vec![];

    // generate inputs of different lengths
    for length in 0..6 {
        // generate input & hash
        let input = rand_fields(rng, length);
        let output = match param_type {
            ParamType::Legacy => poseidon::<constants::PlonkSpongeConstantsLegacy>(
                &input,
                pasta::fp_legacy::static_params(),
            ),
            ParamType::Kimchi => poseidon::<constants::PlonkSpongeConstantsKimchi>(
                &input,
                pasta::fp_kimchi::static_params(),
            ),
        };

        // serialize input & output
        let input = input
            .into_iter()
            .map(|elem| {
                let mut input_bytes = vec![];
                elem.into_bigint()
                    .serialize_uncompressed(&mut input_bytes)
                    .expect("canonical serialiation should work");

                match mode {
                    Mode::Hex => hex::encode(&input_bytes),
                    Mode::B10 => BigUint::from_bytes_le(&input_bytes).to_string(),
                }
            })
            .collect();
        let mut output_bytes = vec![];
        output
            .into_bigint()
            .serialize_uncompressed(&mut output_bytes)
            .expect("canonical serialization should work");

        // add vector
        test_vectors.push(TestVector {
            input,
            output: match mode {
                Mode::Hex => hex::encode(&output_bytes),
                Mode::B10 => BigUint::from_bytes_le(&output_bytes).to_string(),
            },
        })
    }

    let name = match param_type {
        ParamType::Legacy => "legacy",
        ParamType::Kimchi => "kimchi",
    }
    .into();

    TestVectors { name, test_vectors }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn poseidon_test_vectors_regression() {
        use mina_poseidon::pasta;
        let rng = &mut o1_utils::tests::make_test_rng(Some([0u8; 32]));

        // Values are generated w.r.t. the following commit:
        // 1494cf973d40fb276465929eb7db1952c5de7bdc
        // (that still uses arkworks 0.3.0)

        let expected_output_bytes_legacy = [
            [
                27, 50, 81, 182, 145, 45, 130, 237, 199, 139, 187, 10, 92, 136, 240, 198, 253, 225,
                120, 27, 195, 230, 84, 18, 63, 166, 134, 42, 76, 99, 230, 23,
            ],
            [
                233, 146, 98, 4, 142, 113, 119, 69, 253, 205, 96, 42, 59, 82, 126, 158, 124, 46,
                91, 165, 137, 65, 88, 8, 78, 47, 46, 44, 177, 66, 100, 61,
            ],
            [
                31, 143, 157, 47, 185, 84, 125, 2, 84, 161, 192, 39, 31, 244, 0, 66, 165, 153, 39,
                232, 47, 208, 151, 215, 250, 114, 63, 133, 81, 232, 194, 58,
            ],
            [
                153, 120, 16, 250, 143, 51, 135, 158, 104, 156, 128, 128, 33, 215, 241, 207, 48,
                47, 48, 240, 7, 87, 84, 228, 61, 194, 247, 93, 118, 187, 57, 32,
            ],
            [
                249, 48, 174, 91, 239, 32, 152, 227, 183, 25, 73, 233, 135, 140, 175, 86, 89, 137,
                127, 59, 158, 177, 113, 31, 41, 106, 153, 207, 183, 64, 236, 63,
            ],
            [
                70, 27, 110, 192, 143, 211, 169, 195, 112, 51, 239, 212, 9, 207, 84, 132, 147, 176,
                3, 178, 245, 0, 219, 132, 93, 93, 31, 210, 255, 206, 27, 2,
            ],
        ];

        let expected_output_bytes_kimchi = [
            [
                168, 235, 158, 224, 243, 0, 70, 48, 138, 187, 250, 93, 32, 175, 115, 200, 27, 189,
                171, 194, 91, 69, 151, 133, 2, 77, 4, 82, 40, 190, 173, 47,
            ],
            [
                194, 127, 92, 204, 27, 156, 169, 110, 191, 207, 34, 111, 254, 28, 202, 241, 89,
                145, 245, 226, 223, 247, 32, 48, 223, 109, 141, 29, 230, 181, 28, 13,
            ],
            [
                238, 26, 57, 207, 87, 2, 255, 206, 108, 78, 212, 92, 105, 193, 255, 227, 103, 185,
                123, 134, 79, 154, 104, 138, 78, 128, 170, 185, 149, 74, 14, 10,
            ],
            [
                252, 66, 64, 58, 146, 197, 79, 63, 196, 10, 116, 66, 72, 177, 170, 234, 252, 154,
                82, 137, 234, 3, 117, 226, 73, 211, 32, 4, 150, 196, 133, 33,
            ],
            [
                42, 33, 199, 187, 104, 139, 231, 56, 52, 166, 8, 70, 141, 53, 158, 96, 175, 246,
                75, 186, 160, 9, 17, 203, 83, 113, 240, 208, 235, 33, 111, 41,
            ],
            [
                133, 233, 196, 82, 62, 17, 13, 12, 173, 230, 192, 216, 56, 126, 197, 152, 164, 155,
                205, 238, 73, 116, 220, 196, 21, 134, 120, 39, 171, 177, 119, 25,
            ],
        ];

        let expected_output_0_hex_legacy =
            "1b3251b6912d82edc78bbb0a5c88f0c6fde1781bc3e654123fa6862a4c63e617";
        let expected_output_0_hex_kimchi =
            "a8eb9ee0f30046308abbfa5d20af73c81bbdabc25b459785024d045228bead2f";

        for param_type in [ParamType::Legacy, ParamType::Kimchi] {
            let expected_output_bytes = match param_type {
                ParamType::Legacy => &expected_output_bytes_legacy,
                ParamType::Kimchi => &expected_output_bytes_kimchi,
            };

            for length in 0..6 {
                // generate input & hash
                let input = rand_fields(rng, length);
                let output = match param_type {
                    ParamType::Legacy => poseidon::<constants::PlonkSpongeConstantsLegacy>(
                        &input,
                        pasta::fp_legacy::static_params(),
                    ),
                    ParamType::Kimchi => poseidon::<constants::PlonkSpongeConstantsKimchi>(
                        &input,
                        pasta::fp_kimchi::static_params(),
                    ),
                };

                let mut output_bytes = vec![];
                output
                    .into_bigint()
                    .serialize_uncompressed(&mut output_bytes)
                    .expect("canonical serialization should work");

                assert!(output_bytes == expected_output_bytes[length as usize]);
            }

            let expected_output_0_hex = match param_type {
                ParamType::Legacy => expected_output_0_hex_legacy,
                ParamType::Kimchi => expected_output_0_hex_kimchi,
            };

            let test_vectors_hex = generate(Mode::Hex, param_type);
            assert!(test_vectors_hex.test_vectors[0].output == expected_output_0_hex);
        }
    }
}
