use crate::proof::Proof;
use crate::verification_key::VerificationKey;
use ark_ec::{group::Group, msm::VariableBaseMSM, PairingEngine};
use ark_ff::{One, PrimeField};

pub fn verify<Pair: PairingEngine>(
    public_input: &[<<Pair::G1Projective as Group>::ScalarField as PrimeField>::BigInt],
    proof: &Proof<Pair::G1Affine, Pair::G2Affine>,
    verification_key: &VerificationKey<Pair::G1Affine, Pair::G2Affine>,
) -> bool {
    if public_input.len() != verification_key.public_input_commitments.len() {
        return false;
    }
    let public_input =
        VariableBaseMSM::multi_scalar_mul(&verification_key.public_input_commitments, public_input);

    let to_loop = [
        (
            ark_ec::prepare_g1::<Pair>(proof.neg_a + proof.neg_a_delayed),
            ark_ec::prepare_g2::<Pair>(proof.b),
        ),
        (
            ark_ec::prepare_g1::<Pair>(proof.neg_a_delayed),
            ark_ec::prepare_g2::<Pair>(verification_key.left_delayed_fixed_randomizer),
        ),
        (
            ark_ec::prepare_g1::<Pair>(verification_key.left_fixed_randomizer),
            ark_ec::prepare_g2::<Pair>(verification_key.right_fixed_randomizer),
        ),
        (
            ark_ec::prepare_g1::<Pair>(public_input),
            ark_ec::prepare_g2::<Pair>(verification_key.public_input_randomizer),
        ),
        (
            ark_ec::prepare_g1::<Pair>(proof.c),
            ark_ec::prepare_g2::<Pair>(verification_key.output_fixed_randomizer),
        ),
    ];

    Pair::final_exponentiation(&(Pair::miller_loop(&to_loop))).unwrap() == Pair::Fqk::one()
}
