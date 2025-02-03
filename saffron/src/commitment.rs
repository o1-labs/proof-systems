use ark_ec::AffineRepr;
use ark_ff::One;
use ark_poly::{Evaluations, Radix2EvaluationDomain as D};
use kimchi::curve::KimchiCurve;
use mina_poseidon::FqSponge;
use poly_commitment::{
    commitment::{absorb_commitment, CommitmentCurve},
    ipa::SRS,
    PolyComm, SRS as _,
};
use rayon::prelude::*;
use tracing::instrument;

#[instrument(skip_all, level = "debug")]
pub fn commit_to_field_elems<G: CommitmentCurve>(
    srs: &SRS<G>,
    domain: D<G::ScalarField>,
    field_elems: Vec<Vec<G::ScalarField>>,
) -> Vec<PolyComm<G>> {
    field_elems
        .par_iter()
        .map(|chunk| {
            let evals = Evaluations::from_vec_and_domain(chunk.to_vec(), domain);
            srs.commit_evaluations_non_hiding(domain, &evals)
        })
        .collect()
}

#[instrument(skip_all, level = "debug")]
pub fn fold_commitments<
    G: AffineRepr,
    EFqSponge: Clone + FqSponge<G::BaseField, G, G::ScalarField>,
>(
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

pub fn user_commitment<
    G: KimchiCurve,
    EFqSponge: Clone + FqSponge<G::BaseField, G, G::ScalarField>,
>(
    srs: &SRS<G>,
    domain: D<G::ScalarField>,
    field_elems: Vec<Vec<G::ScalarField>>,
) -> PolyComm<G> {
    let commitments = commit_to_field_elems(srs, domain, field_elems);
    let (commitment, _) = {
        let mut sponge = EFqSponge::new(G::other_curve_sponge_params());
        fold_commitments(&mut sponge, &commitments)
    };
    commitment
}
