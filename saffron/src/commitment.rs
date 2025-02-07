use ark_ec::AffineRepr;
use ark_ff::One;
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
use tracing::instrument;

use crate::utils::Diff;

#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(bound = "G::ScalarField: CanonicalDeserialize + CanonicalSerialize")]
pub struct Commitment<G: CommitmentCurve> {
    pub commitments: Vec<PolyComm<G>>,
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub alpha: G::ScalarField,
    pub folded_commitment: PolyComm<G>,
}

impl<G: KimchiCurve> Commitment<G> {
    pub fn from_commitments<EFqSponge>(
        commitments: Vec<PolyComm<G>>,
        sponge: &mut EFqSponge,
    ) -> Self
    where
        EFqSponge: FqSponge<G::BaseField, G, G::ScalarField>,
    {
        let (folded_commitment, alpha) = fold_commitments(sponge, &commitments);
        Self {
            commitments,
            alpha,
            folded_commitment,
        }
    }

    pub fn update<EFqSponge>(
        &mut self,
        srs: &SRS<G>,
        domain: D<G::ScalarField>,
        diff: &Diff<G::ScalarField>,
    ) where
        EFqSponge: FqSponge<G::BaseField, G, G::ScalarField>,
    {
        let ds: Vec<PolyComm<G>> = diff
            .evaluation_diffs
            .iter()
            .map(|diff| {
                let evals = Evaluations::from_vec_and_domain(diff.to_vec(), domain);
                srs.commit_evaluations_non_hiding(domain, &evals)
            })
            .collect();
        let commitments: Vec<PolyComm<G>> = self
            .commitments
            .iter()
            .zip(ds.iter())
            .map(|(c, d)| c + d)
            .collect();
        let mut sponge = EFqSponge::new(G::other_curve_sponge_params());
        *self = Commitment::from_commitments(commitments, &mut sponge);
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
    Commitment::from_commitments(commitments, &mut sponge)
}

#[instrument(skip_all, level = "debug")]
fn fold_commitments<G: AffineRepr, EFqSponge: FqSponge<G::BaseField, G, G::ScalarField>>(
    sponge: &mut EFqSponge,
    commitments: &[PolyComm<G>],
) -> (PolyComm<G>, G::ScalarField) {
    for commitment in commitments {
        absorb_commitment(sponge, commitment)
    }
    let alpha = sponge.challenge();
    let powers: Vec<G::ScalarField> = commitments
        .iter()
        .scan(G::ScalarField::one(), |acc, _| {
            let res = *acc;
            *acc *= alpha;
            Some(res)
        })
        .collect::<Vec<_>>();
    (
        PolyComm::multi_scalar_mul(&commitments.iter().collect::<Vec<_>>(), &powers),
        alpha,
    )
}
