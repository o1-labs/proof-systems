//! Implement folding environments and folding configurations for Plonkish
//! proving systems.

use std::{array, ops::Index};

use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::{FftField, Zero};
use ark_poly::{Evaluations, Radix2EvaluationDomain};
use itertools::Itertools;
use kimchi::circuits::gate::CurrOrNext;
use kimchi_msm::{columns::Column, witness::Witness as GenericWitness};
use mina_poseidon::FqSponge;
use poly_commitment::{
    commitment::{absorb_commitment, CommitmentCurve},
    srs::SRS,
    PolyComm, SRS as _,
};
use rayon::iter::{IntoParallelIterator as _, ParallelIterator as _};

use crate::{
    expressions::FoldingColumnTrait, Alphas, FoldingConfig, FoldingEnv, Instance, Side, Witness,
};

pub(crate) type ScalarField<C> = <<C as FoldingConfig>::Curve as AffineCurve>::ScalarField;

// Implementation to be compatible with folding if we use generic column constraints
impl FoldingColumnTrait for Column {
    fn is_witness(&self) -> bool {
        match self {
            Column::Relation(_) => true,
            Column::FixedSelector(_) => false,
            Column::LookupPartialSum(_)
            | Column::LookupMultiplicity(_)
            | Column::LookupFixedTable(_)
            | Column::LookupAggregation => {
                todo!("Lookup columns have not been tested yet for folding")
            }
            Column::DynamicSelector(_) => {
                unimplemented!("Dynamic selectors should not be used in Plonkish relations. It is meant to be used by the folding library.")
            }
        }
    }
}

/// Represents an provable trace.
/// A trace is provable if it can be used to prove the correctness of the
/// computation it embeds.
/// For now, the only requirement is to be able to return the length of
/// the computation, which is commonly named the domain size.
pub trait ProvableTrace {
    fn domain_size(&self) -> usize;
}

#[derive(Clone, Debug)]
pub struct PlonkishInstance<const N_COL: usize, C: CommitmentCurve> {
    pub commitments: [C; N_COL],
    pub alphas: Alphas<<C as AffineCurve>::ScalarField>,
}

impl<const N: usize, G: CommitmentCurve> Instance<G> for PlonkishInstance<N, G> {
    fn combine(a: Self, b: Self, challenge: G::ScalarField) -> Self {
        PlonkishInstance {
            commitments: array::from_fn(|i| {
                a.commitments[i] + b.commitments[i].mul(challenge).into_affine()
            }),
            alphas: Alphas::combine(a.alphas, b.alphas, challenge),
        }
    }

    fn alphas(&self) -> &Alphas<G::ScalarField> {
        &self.alphas
    }
}

/// Includes the data witness columns and also the dynamic selector columns
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PlonkishWitness<const N: usize, F: FftField> {
    pub witness: GenericWitness<N, Evaluations<F, Radix2EvaluationDomain<F>>>,
}

impl<const N: usize, G: CommitmentCurve> Witness<G> for PlonkishWitness<N, G::ScalarField> {
    fn combine(mut a: Self, b: Self, challenge: G::ScalarField) -> Self {
        for (a, b) in (*a.witness.cols).iter_mut().zip(*(b.witness.cols)) {
            for (a, b) in a.evals.iter_mut().zip(b.evals) {
                *a += challenge * b;
            }
        }
        a
    }

    fn rows(&self) -> usize {
        self.witness.cols[0].evals.len()
    }
}

impl<const N: usize, G: CommitmentCurve> PlonkishInstance<N, G> {
    pub fn from_witness<EFqSponge: Clone + FqSponge<G::BaseField, G, G::ScalarField>>(
        w: &GenericWitness<N, Evaluations<G::ScalarField, Radix2EvaluationDomain<G::ScalarField>>>,
        fq_sponge: &mut EFqSponge,
        srs: &SRS<G>,
        domain: Radix2EvaluationDomain<G::ScalarField>,
    ) -> Self {
        let commitments: GenericWitness<3, PolyComm<G>> = (&w)
            .into_par_iter()
            .map(|w| srs.commit_evaluations_non_hiding(domain, w))
            .collect();

        // Absorbing commitments
        (&commitments)
            .into_iter()
            .for_each(|c| absorb_commitment(fq_sponge, c));

        let commitments: [G; N] = commitments
            .into_iter()
            .map(|c| c.elems[0])
            .collect_vec()
            .try_into()
            .unwrap();

        let alpha = fq_sponge.challenge();
        let alphas = Alphas::new(alpha);

        PlonkishInstance {
            commitments,
            alphas,
        }
    }
}

pub struct PlonkishEnvironment<
    'a,
    const N: usize,
    C: FoldingConfig,
    W: Witness<C::Curve>,
    Structure: ProvableTrace,
> {
    /// Structure of the folded circuit
    pub structure: Structure,
    /// Commitments to the witness columns, for both sides
    pub instances: [PlonkishInstance<N, C::Curve>; 2],
    /// Corresponds to the omega evaluations, for both sides
    pub curr_witnesses: [&'a W; 2],
}

impl<
        'a,
        const N: usize,
        W: Witness<C::Curve>,
        C: FoldingConfig,
        Structure: ProvableTrace + Clone,
    > FoldingEnv<ScalarField<C>, PlonkishInstance<N, C::Curve>, W, C::Column, (), ()>
    for PlonkishEnvironment<'a, N, C, W, Structure>
where
    Witness<C::Curve>: Index<
        C::Column,
        Output = Evaluations<ScalarField<C>, Radix2EvaluationDomain<ScalarField<C>>>,
    >,
{
    type Structure = Structure;

    fn new(
        structure: &Self::Structure,
        instances: [&PlonkishInstance<N, C::Curve>; 2],
        witnesses: [&W; 2],
    ) -> Self {
        PlonkishEnvironment {
            // FIXME: This is a clone, but it should be a reference
            structure: structure.clone(),
            instances: [instances[0].clone(), instances[1].clone()],
            curr_witnesses: witnesses,
        }
    }

    fn domain_size(&self) -> usize {
        self.structure.domain_size()
    }

    fn zero_vec(&self) -> Vec<ScalarField<C>> {
        vec![ScalarField::<C>::zero(); self.domain_size()]
    }

    fn col(&self, col: C::Column, curr_or_next: CurrOrNext, side: Side) -> &Vec<ScalarField<C>> {
        let wit = match curr_or_next {
            CurrOrNext::Curr => self.curr_witnesses[side as usize],
            _ => unimplemented!("Only curr is supported for PlonkishEnvironment"),
        };
        // The following is possible because Index is implemented for our circuit witnesses
        wit[col].evals
    }

    fn challenge(&self, _challenge: (), _side: Side) -> ScalarField<C> {
        unimplemented!("There is no challenge")
    }

    fn alpha(&self, i: usize, side: Side) -> ScalarField<C> {
        let instance = &self.instances[side as usize];
        instance.alphas.get(i).unwrap()
    }

    fn selector(&self, _s: &(), _side: Side) -> &Vec<ScalarField<C>> {
        unimplemented!("Selector not implemented for FoldingEnvironment. No selectors are supposed to be used when it is Plonkish relations.")
    }
}

#[derive(Clone, Copy)]
pub struct PlonkishTrace {
    domain_size: usize,
}

impl ProvableTrace for PlonkishTrace {
    fn domain_size(&self) -> usize {
        self.domain_size
    }
}
