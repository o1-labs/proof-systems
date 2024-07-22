use crate::proof::Proof;
use crate::verification_key::VerificationKey;
use ark_ec::{group::Group, msm::VariableBaseMSM, PairingEngine};
use ark_ff::fields::PrimeField;

pub fn verify<Pair: PairingEngine>(
    public_input: &[<<Pair::G1Projective as Group>::ScalarField as PrimeField>::BigInt],
    proof: &Proof<Pair::G1Affine, Pair::G2Affine>,
    verification_key: &VerificationKey<Pair::G1Affine, Pair::G2Affine>,
) -> bool {
    if public_input.len() != verification_key.public_input_commitments.len() {
        return false;
    }

    // TODO: Improve a lot

    let product = Pair::pairing(proof.a, proof.b);
    // TODO: This is static, just cache it directly in the verification key.
    let product_fixed_randomizer = Pair::pairing(
        verification_key.left_fixed_randomizer,
        verification_key.right_fixed_randomizer,
    );
    let public = {
        let public_input = VariableBaseMSM::multi_scalar_mul(
            &verification_key.public_input_commitments,
            public_input,
        );
        Pair::pairing(public_input, verification_key.public_input_randomizer)
    };
    let output = Pair::pairing(proof.c, verification_key.output_fixed_randomizer);
    product == product_fixed_randomizer + public + output
}
