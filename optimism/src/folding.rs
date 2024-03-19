use ark_bn254;
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_poly::{Evaluations, Radix2EvaluationDomain};
use kimchi::folding::{Alphas, Instance, Witness};
use kimchi_msm::witness::Witness as GenericWitness;
use std::array;

// Instantiate it with the desired group and field
pub type Curve = ark_bn254::G1Affine;
pub type Fp = ark_bn254::Fr;

// Does not contain alpha because this one should be provided by folding itself
#[allow(dead_code)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum Challenge {
    Beta,
    Gamma,
    JointCombiner,
}

/// Folding instance containing the commitment to a witness of N columns, challenges for the proof, and the alphas
#[derive(Debug, Clone)]
pub(crate) struct FoldingInstance<const N: usize> {
    pub(crate) commitments: [Curve; N],
    pub(crate) challenges: [Fp; 3],
    pub(crate) alphas: Alphas,
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

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct FoldingWitness<const N: usize> {
    pub(crate) witness: GenericWitness<N, Evaluations<Fp, Radix2EvaluationDomain<Fp>>>,
}

impl<const N: usize> Witness<Curve> for FoldingWitness<N> {
    fn combine(mut a: Self, b: Self, challenge: Fp) -> Self {
        for (a, b) in a.witness.cols.iter_mut().zip(b.witness.cols) {
            for (a, b) in a.evals.iter_mut().zip(b.evals) {
                *a += challenge * b;
            }
        }
        a
    }
}

/// Environment for the folding protocol, for a given number of witness columns and structure
pub(crate) struct FoldingEnvironment<const N: usize, S> {
    /// Structure of the folded circuit
    #[allow(dead_code)]
    pub(crate) structure: S,
    /// Commitments to the witness columns, for both sides
    pub(crate) instances: [FoldingInstance<N>; 2],
    /// Corresponds to the omega evaluations, for both sides
    pub(crate) curr_witnesses: [FoldingWitness<N>; 2],
    /// Corresponds to the zeta*omega evaluations, for both sides
    /// This is curr_witness but left shifted by 1
    pub(crate) next_witnesses: [FoldingWitness<N>; 2],
}
