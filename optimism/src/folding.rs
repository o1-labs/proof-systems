use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::{Field, One, Zero};
use ark_poly::{Evaluations, Radix2EvaluationDomain};
use core::sync::atomic::Ordering;
use folding::{FoldingEnv, Instance, Side, Sponge, Witness};
use kimchi::{
    circuits::{expr::ChallengeTerm, gate::CurrOrNext},
    curve::KimchiCurve,
};
use kimchi_msm::witness::Witness as GenericWitness;
use mina_poseidon::{
    sponge::{DefaultFqSponge, ScalarChallenge},
    FqSponge,
};
use poly_commitment::PolyComm;
use std::{array, iter::successors, ops::Index, rc::Rc, sync::atomic::AtomicUsize};
use strum::EnumCount;
use strum_macros::{EnumCount as EnumCountMacro, EnumIter};

use crate::{BaseSponge as BaseSpongeT, Curve, Fp, DOMAIN_SIZE};

// FIXME: Using a struct as Rust asks for it, but we should change how folding
// uses the sponge.
pub struct BaseSponge(BaseSpongeT);

// TODO: get rid of trait Sponge in folding, and use the one from kimchi
impl Sponge<Curve> for BaseSponge {
    fn challenge(absorb: &[PolyComm<Curve>; 2]) -> Fp {
        // This function does not have a &self because it is meant to absorb and
        // squeeze only once
        let x = DefaultFqSponge::new(Curve::other_curve_sponge_params());
        let mut s = BaseSponge(x);
        s.0.absorb_g(&absorb[0].elems);
        s.0.absorb_g(&absorb[1].elems);
        // Squeeze sponge
        let chal = ScalarChallenge(s.0.challenge());
        let (_, endo_r) = Curve::endos();
        chal.to_field(endo_r)
    }
}

// Does not contain alpha because this one should be provided by folding itself
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, EnumIter, EnumCountMacro)]
pub enum Challenge {
    Beta,
    Gamma,
    JointCombiner,
}

/// The alphas are exceptional, their number cannot be known ahead of time as it
/// will be defined by folding. The values will be computed as powers in new
/// instances, but after folding each alfa will be a linear combination of other
/// alphas, instand of a power of other element. This type represents that,
/// allowing to also recognize which case is present
#[derive(Debug, Clone)]
pub enum Alphas {
    Powers(Fp, Rc<AtomicUsize>),
    Combinations(Vec<Fp>),
}

impl Alphas {
    pub fn new(alpha: Fp) -> Self {
        Self::Powers(alpha, Rc::new(AtomicUsize::from(0)))
    }
    pub fn get(&self, i: usize) -> Option<Fp> {
        match self {
            Alphas::Powers(alpha, count) => {
                let _ = count.fetch_max(i + 1, Ordering::Relaxed);
                let i = [i as u64];
                Some(alpha.pow(i))
            }
            Alphas::Combinations(alphas) => alphas.get(i).cloned(),
        }
    }
    pub fn powers(self) -> Vec<Fp> {
        match self {
            Alphas::Powers(alpha, count) => {
                let n = count.load(Ordering::Relaxed);
                let alphas = successors(Some(Fp::one()), |last| Some(*last * alpha));
                alphas.take(n).collect()
            }
            Alphas::Combinations(c) => c,
        }
    }
    pub fn combine(a: Self, b: Self, challenge: Fp) -> Self {
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

// Needed to transform from expressions to folding expressions
impl From<ChallengeTerm> for Challenge {
    fn from(chal: ChallengeTerm) -> Self {
        match chal {
            ChallengeTerm::Beta => Challenge::Beta,
            ChallengeTerm::Gamma => Challenge::Gamma,
            ChallengeTerm::JointCombiner => Challenge::JointCombiner,
            ChallengeTerm::Alpha => panic!("Alpha not allowed in folding expressions"),
        }
    }
}

/// Folding instance containing the commitment to a witness of N columns,
/// challenges for the proof, and the alphas
#[derive(Debug, Clone)]
pub struct FoldingInstance<const N: usize> {
    /// Commitments to the witness columns, including the dynamic selectors
    pub commitments: [Curve; N],
    /// Challenges for the proof.
    /// We do use 3 challenges:
    /// - β as the evaluation point for the logup argument
    /// - j: the joint combiner for vector lookups
    /// - γ (set to 0 for now)
    pub challenges: [Fp; Challenge::COUNT],
    /// Reuses the Alphas defined in the example of folding
    pub alphas: Alphas,
}

impl<const N: usize> Instance<Curve> for FoldingInstance<N> {
    fn combine(a: Self, b: Self, challenge: Fp) -> Self {
        FoldingInstance {
            commitments: array::from_fn(|i| {
                a.commitments[i] + b.commitments[i].mul(challenge).into_affine()
            }),
            challenges: array::from_fn(|i| a.challenges[i] + challenge * b.challenges[i]),
            alphas: Alphas::combine(a.alphas, b.alphas, challenge),
        }
    }
}

/// Includes the data witness columns and also the dynamic selector columns
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct FoldingWitness<const N: usize> {
    pub witness: GenericWitness<N, Evaluations<Fp, Radix2EvaluationDomain<Fp>>>,
}

impl<const N: usize> Witness<Curve> for FoldingWitness<N> {
    fn combine(mut a: Self, b: Self, challenge: Fp) -> Self {
        for (a, b) in (*a.witness.cols).iter_mut().zip(*(b.witness.cols)) {
            for (a, b) in a.evals.iter_mut().zip(b.evals) {
                *a += challenge * b;
            }
        }
        a
    }
}

/// Environment for the folding protocol, for a given number of witness columns
/// and structure
pub struct FoldingEnvironment<const N: usize, Structure> {
    /// Structure of the folded circuit (not used right now)
    #[allow(dead_code)]
    pub structure: Structure,
    /// Commitments to the witness columns, for both sides
    pub instances: [FoldingInstance<N>; 2],
    /// Corresponds to the omega evaluations, for both sides
    pub curr_witnesses: [FoldingWitness<N>; 2],
    /// Corresponds to the zeta*omega evaluations, for both sides
    /// This is curr_witness but left shifted by 1
    pub next_witnesses: [FoldingWitness<N>; 2],
}

impl<const N: usize, Col, Selector: Copy + Clone, Structure: Clone>
    FoldingEnv<Fp, FoldingInstance<N>, FoldingWitness<N>, Col, Challenge, Selector>
    for FoldingEnvironment<N, Structure>
where
    FoldingWitness<N>: Index<Col, Output = Evaluations<Fp, Radix2EvaluationDomain<Fp>>>,
    FoldingWitness<N>: Index<Selector, Output = Evaluations<Fp, Radix2EvaluationDomain<Fp>>>,
{
    type Structure = Structure;

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

    fn selector(&self, s: &Selector, side: Side) -> &Vec<Fp> {
        let witness = &self.curr_witnesses[side as usize];
        &witness[*s].evals
    }
}
