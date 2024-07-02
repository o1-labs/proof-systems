/// Provides definition of plonkish language related instance,
/// witness, and tools to work with them. The IVC is specialized for
/// exactly the plonkish language.
use ark_ec::ProjectiveCurve;
use ark_ff::{FftField, Field, One};
use ark_poly::{Evaluations, Radix2EvaluationDomain as R2D};
use folding::{instance_witness::Foldable, Alphas, Instance, Witness};
use itertools::Itertools;
use kimchi::{self, circuits::expr::ChallengeTerm, curve::KimchiCurve};
use kimchi_msm::{columns::Column, witness::Witness as GenericWitness};
use mina_poseidon::FqSponge;
use poly_commitment::{
    commitment::{absorb_commitment, CommitmentCurve},
    srs::SRS,
    PolyComm, SRS as _,
};
use rayon::iter::{IntoParallelIterator as _, ParallelIterator as _};
use std::ops::Index;
use strum_macros::{EnumCount as EnumCountMacro, EnumIter};

/// Vector field over F. Something like a vector.
pub trait CombinableEvals<F: Field> {
    fn e_as_slice(&self) -> &[F];
    fn e_as_mut_slice(&mut self) -> &mut [F];
}

impl<F: FftField> CombinableEvals<F> for Evaluations<F, R2D<F>> {
    fn e_as_slice(&self) -> &[F] {
        self.evals.as_slice()
    }
    fn e_as_mut_slice(&mut self) -> &mut [F] {
        self.evals.as_mut_slice()
    }
}

impl<F: FftField> CombinableEvals<F> for Vec<F> {
    fn e_as_slice(&self) -> &[F] {
        self.as_slice()
    }
    fn e_as_mut_slice(&mut self) -> &mut [F] {
        self.as_mut_slice()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PlonkishWitnessGeneric<const N_COL: usize, const N_FSEL: usize, F: Field, Evals> {
    pub witness: GenericWitness<N_COL, Evals>,
    // This does not have to be part of the witness... can be a static
    // precompiled object.
    pub fixed_selectors: GenericWitness<N_FSEL, Evals>,
    pub phantom: std::marker::PhantomData<F>,
}

pub type PlonkishWitness<const N_COL: usize, const N_FSEL: usize, F> =
    PlonkishWitnessGeneric<N_COL, N_FSEL, F, Evaluations<F, R2D<F>>>;

impl<const N_COL: usize, const N_FSEL: usize, F: Field, Evals: CombinableEvals<F>> Foldable<F>
    for PlonkishWitnessGeneric<N_COL, N_FSEL, F, Evals>
{
    fn combine(mut a: Self, b: Self, challenge: F) -> Self {
        for (a, b) in (*a.witness.cols).iter_mut().zip(*(b.witness.cols)) {
            for (a, b) in (a.e_as_mut_slice()).iter_mut().zip(b.e_as_slice()) {
                *a += *b * challenge;
            }
        }
        a
    }
}

impl<
        const N_COL: usize,
        const N_FSEL: usize,
        Curve: CommitmentCurve,
        Evals: CombinableEvals<Curve::ScalarField>,
    > Witness<Curve> for PlonkishWitnessGeneric<N_COL, N_FSEL, Curve::ScalarField, Evals>
{
}

impl<const N_COL: usize, const N_FSEL: usize, F: FftField, Evals: CombinableEvals<F>> Index<Column>
    for PlonkishWitnessGeneric<N_COL, N_FSEL, F, Evals>
{
    type Output = [F];

    /// Map a column alias to the corresponding witness column.
    fn index(&self, index: Column) -> &Self::Output {
        match index {
            Column::Relation(i) => self.witness.cols[i].e_as_slice(),
            Column::FixedSelector(i) => self.fixed_selectors[i].e_as_slice(),
            other => panic!("Invalid column index: {other:?}"),
        }
    }
}

// for selectors, () in this case as we have none
impl<const N_COL: usize, const N_FSEL: usize, F: FftField> Index<()>
    for PlonkishWitness<N_COL, N_FSEL, F>
{
    type Output = Vec<F>;

    fn index(&self, _index: ()) -> &Self::Output {
        unreachable!()
    }
}

#[derive(Clone, Debug)]

pub struct PlonkishInstance<
    G: KimchiCurve,
    const N_COL: usize,
    const N_CHALS: usize,
    const N_ALPHAS: usize,
> {
    pub commitments: [G; N_COL],
    pub challenges: [G::ScalarField; N_CHALS],
    pub alphas: Alphas<G::ScalarField>,
    pub blinder: G::ScalarField,
}

impl<G: KimchiCurve, const N_COL: usize, const N_CHALS: usize, const N_ALPHAS: usize>
    Foldable<G::ScalarField> for PlonkishInstance<G, N_COL, N_CHALS, N_ALPHAS>
{
    fn combine(a: Self, b: Self, challenge: G::ScalarField) -> Self {
        Self {
            commitments: std::array::from_fn(|i| {
                a.commitments[i] + b.commitments[i].mul(challenge).into_affine()
            }),
            challenges: std::array::from_fn(|i| a.challenges[i] + challenge * b.challenges[i]),
            alphas: Alphas::combine(a.alphas, b.alphas, challenge),
            blinder: a.blinder + challenge * b.blinder,
        }
    }
}

impl<G: KimchiCurve, const N_COL: usize, const N_CHALS: usize, const N_ALPHAS: usize> Instance<G>
    for PlonkishInstance<G, N_COL, N_CHALS, N_ALPHAS>
{
    fn to_absorb(&self) -> (Vec<G::ScalarField>, Vec<G>) {
        // FIXME: check!!!!
        let mut scalars = Vec::new();
        let mut points = Vec::new();
        points.extend(self.commitments);
        scalars.extend(self.challenges);
        scalars.extend(self.alphas.clone().powers());
        (scalars, points)
    }

    fn get_alphas(&self) -> &Alphas<G::ScalarField> {
        &self.alphas
    }

    fn get_blinder(&self) -> G::ScalarField {
        self.blinder
    }
}

// Implementation for 3 challenges; only for now.
impl<G: KimchiCurve, const N_COL: usize, const N_ALPHAS: usize>
    PlonkishInstance<G, N_COL, 3, N_ALPHAS>
{
    #[allow(dead_code)]
    pub fn from_witness<EFqSponge: FqSponge<G::BaseField, G, G::ScalarField>>(
        w: &GenericWitness<N_COL, Evaluations<G::ScalarField, R2D<G::ScalarField>>>,
        fq_sponge: &mut EFqSponge,
        srs: &SRS<G>,
        domain: R2D<G::ScalarField>,
    ) -> Self {
        let blinder = G::ScalarField::one();

        let commitments: GenericWitness<N_COL, PolyComm<G>> = w
            .into_par_iter()
            .map(|w| {
                let blinder = PolyComm::new(vec![blinder; 1]);
                let unblinded = srs.commit_evaluations_non_hiding(domain, w);
                srs.mask_custom(unblinded, &blinder).unwrap().commitment
            })
            .collect();

        // Absorbing commitments
        (&commitments)
            .into_iter()
            .for_each(|c| absorb_commitment(fq_sponge, c));

        let commitments: [G; N_COL] = commitments
            .into_iter()
            .map(|c| c.elems[0])
            .collect_vec()
            .try_into()
            .unwrap();

        let beta = fq_sponge.challenge();
        let gamma = fq_sponge.challenge();
        let joint_combiner = fq_sponge.challenge();
        let challenges = [beta, gamma, joint_combiner];

        let alpha = fq_sponge.challenge();
        let alphas = Alphas::new_sized(alpha, N_ALPHAS);

        Self {
            commitments,
            challenges,
            alphas,
            blinder,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, EnumIter, EnumCountMacro)]
pub enum PlonkishChallenge {
    Beta,
    Gamma,
    JointCombiner,
}

impl From<ChallengeTerm> for PlonkishChallenge {
    fn from(chal: ChallengeTerm) -> Self {
        match chal {
            ChallengeTerm::Beta => PlonkishChallenge::Beta,
            ChallengeTerm::Gamma => PlonkishChallenge::Gamma,
            ChallengeTerm::JointCombiner => PlonkishChallenge::JointCombiner,
            ChallengeTerm::Alpha => panic!("Alpha not allowed in folding expressions"),
        }
    }
}

impl<G: KimchiCurve, const N_COL: usize, const N_ALPHAS: usize> Index<PlonkishChallenge>
    for PlonkishInstance<G, N_COL, 3, N_ALPHAS>
{
    type Output = G::ScalarField;

    fn index(&self, index: PlonkishChallenge) -> &Self::Output {
        match index {
            PlonkishChallenge::Beta => &self.challenges[0],
            PlonkishChallenge::Gamma => &self.challenges[1],
            PlonkishChallenge::JointCombiner => &self.challenges[2],
        }
    }
}
