use crate::DOMAIN_SIZE;
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::{FftField, Zero};
use ark_poly::{Evaluations, Radix2EvaluationDomain};
use folding::{Alphas, FoldingConfig, FoldingEnv, Instance, Side, Witness};
use kimchi::circuits::{expr::ChallengeTerm, gate::CurrOrNext};
use kimchi_msm::witness::Witness as GenericWitness;
use poly_commitment::commitment::CommitmentCurve;
use std::{array, ops::Index};
use strum::EnumCount;
use strum_macros::{EnumCount as EnumCountMacro, EnumIter};

// Simple type alias as ScalarField/BaseField is often used. Reduce type
// complexity for clippy.
// Should be moved into FoldingConfig, but associated type defaults are unstable
// at the moment.
pub(crate) type ScalarField<C> = <<C as FoldingConfig>::Curve as AffineCurve>::ScalarField;
pub(crate) type BaseField<C> = <<C as FoldingConfig>::Curve as AffineCurve>::BaseField;

// Does not contain alpha because this one should be provided by folding itself
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, EnumIter, EnumCountMacro)]
pub enum Challenge {
    Beta,
    Gamma,
    JointCombiner,
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
pub struct FoldingInstance<const N: usize, G: CommitmentCurve> {
    /// Commitments to the witness columns, including the dynamic selectors
    pub commitments: [G; N],
    /// Challenges for the proof.
    /// We do use 3 challenges:
    /// - β as the evaluation point for the logup argument
    /// - j: the joint combiner for vector lookups
    /// - γ (set to 0 for now)
    pub challenges: [<G as AffineCurve>::ScalarField; Challenge::COUNT],
    /// Reuses the Alphas defined in the example of folding
    pub alphas: Alphas<<G as AffineCurve>::ScalarField>,
}

impl<const N: usize, G: CommitmentCurve> Instance<G> for FoldingInstance<N, G> {
    fn combine(a: Self, b: Self, challenge: G::ScalarField) -> Self {
        FoldingInstance {
            commitments: array::from_fn(|i| {
                a.commitments[i] + b.commitments[i].mul(challenge).into_affine()
            }),
            challenges: array::from_fn(|i| a.challenges[i] + challenge * b.challenges[i]),
            alphas: Alphas::combine(a.alphas, b.alphas, challenge),
        }
    }

    fn alphas(&self) -> &Alphas<G::ScalarField> {
        &self.alphas
    }
}

impl<const N: usize, G: CommitmentCurve> Index<Challenge> for FoldingInstance<N, G> {
    type Output = G::ScalarField;

    fn index(&self, index: Challenge) -> &Self::Output {
        match index {
            Challenge::Beta => &self.challenges[0],
            Challenge::Gamma => &self.challenges[1],
            Challenge::JointCombiner => &self.challenges[2],
        }
    }
}

/// Includes the data witness columns and also the dynamic selector columns
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct FoldingWitness<const N: usize, F: FftField> {
    pub witness: GenericWitness<N, Evaluations<F, Radix2EvaluationDomain<F>>>,
}

impl<const N: usize, G: CommitmentCurve> Witness<G> for FoldingWitness<N, G::ScalarField> {
    fn combine(mut a: Self, b: Self, challenge: G::ScalarField) -> Self {
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
pub struct FoldingEnvironment<const N: usize, G: CommitmentCurve> {
    /// Structure of the folded circuit (not used right now)
    pub structure: (),
    /// Commitments to the witness columns, for both sides
    pub instances: [FoldingInstance<N, G>; 2],
    /// Corresponds to the omega evaluations, for both sides
    pub curr_witnesses: [FoldingWitness<N, G::ScalarField>; 2],
    /// Corresponds to the zeta*omega evaluations, for both sides
    /// This is curr_witness but left shifted by 1
    pub next_witnesses: [FoldingWitness<N, G::ScalarField>; 2],
}

impl<const N: usize, G: CommitmentCurve, Col, Selector: Copy + Clone>
    FoldingEnv<
        G::ScalarField,
        FoldingInstance<N, G>,
        FoldingWitness<N, G::ScalarField>,
        Col,
        Challenge,
        Selector,
    > for FoldingEnvironment<N, G>
where
    FoldingWitness<N, G::ScalarField>:
        Index<Col, Output = Evaluations<G::ScalarField, Radix2EvaluationDomain<G::ScalarField>>>,
    FoldingWitness<N, G::ScalarField>: Index<
        Selector,
        Output = Evaluations<G::ScalarField, Radix2EvaluationDomain<G::ScalarField>>,
    >,
{
    type Structure = ();

    fn new(
        _structure: &Self::Structure,
        instances: [&FoldingInstance<N, G>; 2],
        witnesses: [&FoldingWitness<N, G::ScalarField>; 2],
    ) -> Self {
        let curr_witnesses = [witnesses[0].clone(), witnesses[1].clone()];
        let mut next_witnesses = curr_witnesses.clone();
        for side in next_witnesses.iter_mut() {
            for col in side.witness.cols.iter_mut() {
                col.evals.rotate_left(1);
            }
        }
        FoldingEnvironment {
            structure: (),
            instances: [instances[0].clone(), instances[1].clone()],
            curr_witnesses,
            next_witnesses,
        }
    }

    fn zero_vec(&self) -> Vec<G::ScalarField> {
        vec![G::ScalarField::zero(); DOMAIN_SIZE]
    }

    fn col(&self, col: Col, curr_or_next: CurrOrNext, side: Side) -> &Vec<G::ScalarField> {
        let wit = match curr_or_next {
            CurrOrNext::Curr => &self.curr_witnesses[side as usize],
            CurrOrNext::Next => &self.next_witnesses[side as usize],
        };
        // The following is possible because Index is implemented for our circuit witnesses
        &wit[col].evals
    }

    fn challenge(&self, challenge: Challenge, side: Side) -> G::ScalarField {
        match challenge {
            Challenge::Beta => self.instances[side as usize].challenges[0],
            Challenge::Gamma => self.instances[side as usize].challenges[1],
            Challenge::JointCombiner => self.instances[side as usize].challenges[2],
        }
    }

    fn alpha(&self, i: usize, side: Side) -> G::ScalarField {
        let instance = &self.instances[side as usize];
        instance.alphas.get(i).unwrap()
    }

    fn selector(&self, s: &Selector, side: Side) -> &Vec<G::ScalarField> {
        let witness = &self.curr_witnesses[side as usize];
        &witness[*s].evals
    }
}
