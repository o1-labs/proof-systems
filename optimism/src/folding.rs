use ark_bn254;
use ark_ec::short_weierstrass_jacobian::GroupAffine;
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
use poly_commitment::{commitment::CommitmentCurve, PolyComm, SRS};
use std::{
    array,
    iter::successors,
    rc::Rc,
    sync::atomic::{AtomicUsize, Ordering},
};

// Instantiate it with the desired group and field
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

pub(crate) struct FoldingWitness<const N: usize> {
    witness: [Evaluations<Fp, Radix2EvaluationDomain<Fp>>; N],
}

impl<const N: usize> Witness<Curve> for FoldingWitness<N> {
    fn combine(mut a: Self, b: Self, challenge: Fp) -> Self {
        for (a, b) in a.witness.iter_mut().zip(b.witness) {
            for (a, b) in a.evals.iter_mut().zip(b.evals) {
                *a += challenge * b;
            }
        }
        a
    }
}
