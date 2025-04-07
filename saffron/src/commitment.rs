use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use kimchi::curve::KimchiCurve;
use mina_poseidon::FqSponge;
use o1_utils::field_helpers::pows;
use poly_commitment::{ipa::SRS, SRS as _};
use rayon::prelude::*;
use tracing::instrument;

#[instrument(skip_all, level = "debug")]
pub fn commit_to_field_elems<G: KimchiCurve>(srs: &SRS<G>, data: &[G::ScalarField]) -> Vec<G>
where
    <G as AffineRepr>::Group: VariableBaseMSM,
{
    let basis: Vec<G> = srs
        .get_lagrange_basis_from_domain_size(crate::SRS_SIZE)
        .iter()
        .map(|x| x.chunks[0])
        .collect();

    let commitments_projective = (0..data.len() / crate::SRS_SIZE)
        .into_par_iter()
        .map(|idx| {
            G::Group::msm(
                &basis,
                &data[crate::SRS_SIZE * idx..crate::SRS_SIZE * (idx + 1)],
            )
            .unwrap()
        })
        .collect::<Vec<_>>();

    let commitments = G::Group::normalize_batch(commitments_projective.as_slice());

    commitments
}

/// Takes commitments C_i, computes α = hash(C_0 || C_1 || ... || C_n),
/// returns ∑ α^i C_i.
#[instrument(skip_all, level = "debug")]
pub fn combine_commitments<G: AffineRepr, EFqSponge: FqSponge<G::BaseField, G, G::ScalarField>>(
    sponge: &mut EFqSponge,
    commitments: &[G],
) -> (G, G::ScalarField) {
    for commitment in commitments.iter() {
        sponge.absorb_g(std::slice::from_ref(commitment))
    }
    let alpha = sponge.challenge();
    let powers_of_alpha = pows(commitments.len(), alpha);
    let combined_data_commitment =
    // Using unwrap() is safe here, as err is returned when commitments and powers have different lengths,
    // and powers are built with commitment.len().
        G::Group::msm(commitments, powers_of_alpha.as_slice()).unwrap().into_affine();

    (combined_data_commitment, alpha)
}
