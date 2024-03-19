use ark_bn254;
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::Zero;
use ark_poly::{Evaluations, Radix2EvaluationDomain};
use kimchi::{
    circuits::gate::CurrOrNext,
    folding::{Alphas, FoldingEnv, Instance, Side, Witness},
};
use kimchi_msm::witness::Witness as GenericWitness;
use std::{array, ops::Index};

use crate::DOMAIN_SIZE;

// Instantiate it with the desired group and field
pub type Fp = ark_bn254::Fr;
pub type Curve = ark_bn254::G1Affine;

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

impl<const N: usize, Col, S: Clone>
    FoldingEnv<Fp, FoldingInstance<N>, FoldingWitness<N>, Col, Challenge>
    for FoldingEnvironment<N, S>
where
    FoldingWitness<N>: Index<Col, Output = Evaluations<Fp, Radix2EvaluationDomain<Fp>>>,
{
    type Structure = S;

    fn new(
        structure: &Self::Structure,
        instances: [&FoldingInstance<N>; 2],
        witnesses: [&FoldingWitness<N>; 2],
    ) -> Self {
        let curr_witnesses = [witnesses[0].clone(), witnesses[1].clone()];
        let mut next_witnesses = curr_witnesses.clone();
        for side in next_witnesses.iter_mut() {
            for col in side.witness.cols.iter_mut() {
                col.evals.rotate_left(1);
            }
        }
        FoldingEnvironment {
            structure: structure.clone(),
            instances: [instances[0].clone(), instances[1].clone()],
            curr_witnesses,
            next_witnesses,
        }
    }

    fn zero_vec(&self) -> Vec<Fp> {
        vec![Fp::zero(); DOMAIN_SIZE]
    }

    fn col(&self, col: Col, curr_or_next: CurrOrNext, side: Side) -> &Vec<Fp> {
        let wit = match curr_or_next {
            CurrOrNext::Curr => &self.curr_witnesses[side as usize],
            CurrOrNext::Next => &self.next_witnesses[side as usize],
        };
        // The following is possible because Index is implemented for our circuit witnesses
        &wit[col].evals
        // TODO: if selectors columns are used, then return selectors instead of real witness columns
    }

    fn challenge(&self, challenge: Challenge, side: Side) -> Fp {
        match challenge {
            Challenge::Beta => self.instances[side as usize].challenges[0],
            Challenge::Gamma => self.instances[side as usize].challenges[1],
            Challenge::JointCombiner => self.instances[side as usize].challenges[2],
        }
    }

    fn lagrange_basis(&self, _i: usize) -> &Vec<Fp> {
        todo!()
    }

    fn alpha(&self, i: usize, side: Side) -> Fp {
        let instance = &self.instances[side as usize];
        instance.alphas.get(i).unwrap()
    }
}
