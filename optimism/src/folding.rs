use ark_bn254;
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::{Field, One, UniformRand, Zero};
use ark_poly::{EvaluationDomain, Evaluations, Radix2EvaluationDomain};
use kimchi::folding::{
    expressions::FoldingColumnTrait, BaseSponge, FoldingConfig, FoldingEnv, Instance, Side, Sponge,
    Witness,
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

pub type Curve = ark_bn254::G1Affine;
pub type Fp = ark_bn254::Fr;

#[derive(Debug, Clone)]
pub(crate) enum Alphas<F> {
    Powers(F, Rc<AtomicUsize>),
    Combinations(Vec<F>),
}

impl<F: Field> Alphas<F> {
    pub(crate) fn new(alpha: F) -> Self {
        Self::Powers(alpha, Rc::new(AtomicUsize::from(0)))
    }
    pub(crate) fn get(&self, i: usize) -> Option<F> {
        match self {
            Alphas::Powers(alpha, count) => {
                let _ = count.fetch_max(i + 1, Ordering::Relaxed);
                let i = [i as u64];
                Some(alpha.pow(i))
            }
            Alphas::Combinations(alphas) => alphas.get(i).cloned(),
        }
    }
    pub(crate) fn powers(self) -> Vec<F> {
        match self {
            Alphas::Powers(alpha, count) => {
                let n = count.load(Ordering::Relaxed);
                let alphas = successors(Some(F::one()), |last| Some(*last * alpha));
                alphas.take(n).collect()
            }
            Alphas::Combinations(c) => c,
        }
    }
    pub(crate) fn combine(a: Self, b: Self, challenge: F) -> Self {
        let a = a.powers();
        let b = b.powers();
        assert_eq!(a.len(), b.len());
        let comb = a
            .into_iter()
            .zip(b)
            .map(|(a, b)| a + b * challenge)
            .collect();
        Self::Combinations(comb)
    }
}

/// Folding instance containing the commitment to a witness of N columns, challenges for the proof, and the alphas
#[derive(Debug, Clone)]
pub(crate) struct FoldingInstance<const N: usize, G: AffineCurve> {
    commitments: [G; N],
    challenges: [<G as AffineCurve>::ScalarField; 3],
    alphas: Alphas<<G as AffineCurve>::ScalarField>,
}

impl<const N: usize, G: CommitmentCurve> Instance<G> for FoldingInstance<N, G> {
    fn combine(a: Self, b: Self, challenge: <G as AffineCurve>::ScalarField) -> Self {
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
