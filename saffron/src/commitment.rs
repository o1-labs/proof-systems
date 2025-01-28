use ark_ec::AffineRepr;
use ark_ff::One;
use ark_poly::{Evaluations, Radix2EvaluationDomain as D};
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
) -> PolyComm<G> {
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
    PolyComm::multi_scalar_mul(&commitments.iter().collect::<Vec<_>>(), &powers)
}
