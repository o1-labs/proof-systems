use ark_ec::AffineRepr;
use ark_ff::One;
use ark_ff::Zero;
use ark_poly::{Evaluations, Radix2EvaluationDomain as D};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use kimchi::curve::KimchiCurve;
use mina_poseidon::FqSponge;
use poly_commitment::{
    commitment::{absorb_commitment, CommitmentCurve},
    ipa::SRS,
    PolyComm, SRS as _,
};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use std::ops::Add;
use tracing::instrument;

#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(bound = "G::ScalarField: CanonicalDeserialize + CanonicalSerialize")]
pub struct Commitment<G: CommitmentCurve> {
    pub chunks: Vec<PolyComm<G>>,
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    // TODO: we don't want to store alpha and folded anymore
    // We'll delete that in a follow-up commit
    pub alpha: G::ScalarField,
    pub folded: PolyComm<G>,
}

impl<G: KimchiCurve> Commitment<G> {
    pub fn from_chunks<EFqSponge>(chunks: Vec<PolyComm<G>>, sponge: &mut EFqSponge) -> Self
    where
        EFqSponge: FqSponge<G::BaseField, G, G::ScalarField>,
    {
        let folded: PolyComm<G> = fold_commitments::<_, EFqSponge>(G::ScalarField::zero(), &chunks);
        Self {
            chunks,
            alpha: G::ScalarField::zero(),
            folded,
        }
    }

    pub fn update<EFqSponge>(&self, diff: Vec<PolyComm<G>>, sponge: &mut EFqSponge) -> Self
    where
        EFqSponge: FqSponge<G::BaseField, G, G::ScalarField>,
    {
        let new_chunks = self.chunks.iter().zip(diff).map(|(g, d)| g.add(&d));
        Self::from_chunks(new_chunks.collect(), sponge)
    }
}

#[instrument(skip_all, level = "debug")]
pub fn commit_to_field_elems<G: KimchiCurve, EFqSponge>(
    srs: &SRS<G>,
    domain: D<G::ScalarField>,
    field_elems: Vec<Vec<G::ScalarField>>,
) -> Commitment<G>
where
    EFqSponge: Clone + FqSponge<G::BaseField, G, G::ScalarField>,
{
    let commitments = field_elems
        .par_iter()
        .map(|chunk| {
            let evals = Evaluations::from_vec_and_domain(chunk.to_vec(), domain);
            srs.commit_evaluations_non_hiding(domain, &evals)
        })
        .collect();
    let mut sponge = EFqSponge::new(G::other_curve_sponge_params());
    Commitment::from_chunks(commitments, &mut sponge)
}

#[instrument(skip_all, level = "debug")]
fn fold_commitments<G: AffineRepr, EFqSponge: FqSponge<G::BaseField, G, G::ScalarField>>(
    alpha: G::ScalarField,
    commitments: &[PolyComm<G>],
) -> PolyComm<G> {
    let powers: Vec<G::ScalarField> = commitments
        .iter()
        .scan(G::ScalarField::one(), |acc, _| {
            let res = *acc;
            *acc *= alpha;
            Some(res)
        })
        .collect::<Vec<_>>();
    PolyComm::multi_scalar_mul(&commitments.iter().collect::<Vec<_>>(), &powers)
}
