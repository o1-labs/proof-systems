use ark_ff::{One, PrimeField, Zero};
use kimchi::curve::KimchiCurve;

/// This 'auxiliary' prover is intended to be used in a streaming
/// fashion. It will receive a chunk of wire to be looked-up,
/// and output their corresponding contribution to the accumulator.
/// Once the proof is produced, these wires are no longer needed
/// for the rest of the protocol

pub struct AuxiliaryProofInput<F: PrimeField> {
    wires: Vec<Vec<F>>,
    beta_challenge: F,
    gamma_challenge: F,
}

pub fn aux_prove<G: KimchiCurve>(
    input: AuxiliaryProofInput<G::ScalarField>,
) -> Vec<G::ScalarField> {
    let AuxiliaryProofInput {
        wires,
        beta_challenge,
        gamma_challenge,
    } = input;
    let mut to_inv: Vec<G::ScalarField> = wires
        .iter()
        .map(|inner_vec| {
            let (res, _) = inner_vec.iter().fold(
                (beta_challenge, G::ScalarField::one()),
                |(acc, gamma_i), x| (acc + gamma_i * x, gamma_i * gamma_challenge),
            );
            res
        })
        .collect();
    ark_ff::batch_inversion(&mut to_inv);
    let mut partial_sum = G::ScalarField::zero();
    for x in to_inv.iter_mut() {
        partial_sum += x.clone();
        *x = partial_sum;
    }
    to_inv
}
