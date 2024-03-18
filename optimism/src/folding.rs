use std::array;

use ark_bn254;
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::{Field, One, UniformRand, Zero};
use ark_poly::{EvaluationDomain, Evaluations, Radix2EvaluationDomain};
use kimchi::folding::{
    expressions::FoldingColumnTrait, Alphas, BaseSponge, FoldingConfig, FoldingEnv, Instance, Side,
    Sponge, Witness,
};
use mina_poseidon::{
    constants::PlonkSpongeConstantsKimchi,
    sponge::{DefaultFqSponge, ScalarChallenge},
    FqSponge,
};
use poly_commitment::{PolyComm, SRS};

pub type Curve = ark_bn254::G1Affine;
pub type Fp = ark_bn254::Fr;

/// Folding instance containing the commitment to a witness of N columns, challenges for the proof, and the alphas
#[derive(Debug, Clone)]
pub(crate) struct FoldingInstance<const N: usize> {
    commitments: [Curve; N],
    challenges: [Fp; 3],
    alphas: Alphas,
}

impl<const N: usize> Instance<Curve> for FoldingInstance<N> {
    fn combine(a: Self, b: Self, challenge: Fp) -> Self {
        FoldingInstance {
            commitments: array::from_fn(|i| {
                a.commitments[i] + b.commitments[i].mul(challenge).into_affine()
            }),
            challenges: [
                a.challenges[0] + challenge * b.challenges[0],
                a.challenges[1] + challenge * b.challenges[1],
                a.challenges[2] + challenge * b.challenges[2],
            ],
            alphas: Alphas::combine(a.alphas, b.alphas, challenge),
        }
    }
}
