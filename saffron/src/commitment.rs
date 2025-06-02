use crate::{diff::Diff, utils};
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_poly::univariate::DensePolynomial;
use kimchi::curve::KimchiCurve;
use mina_poseidon::FqSponge;
use poly_commitment::{ipa::SRS, SRS as _};
use rayon::prelude::*;
use tracing::instrument;

fn get_lagrange_basis<G: KimchiCurve>(srs: &SRS<G>) -> Vec<G> {
    srs.get_lagrange_basis_from_domain_size(crate::SRS_SIZE)
        .iter()
        .map(|x| x.chunks[0])
        .collect()
}

/// Compute the commitment to `data` ; if the length of `data` is greater than
/// `SRS_SIZE`, the data is splitted in chunks of at most `SRS_SIZE` length.
#[instrument(skip_all, level = "debug")]
pub fn commit_to_field_elems<G: KimchiCurve>(srs: &SRS<G>, data: &[G::ScalarField]) -> Vec<G>
where
    <G as AffineRepr>::Group: VariableBaseMSM,
{
    let basis = get_lagrange_basis(srs);

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

/// Returns the non-hiding commitment to the provided polynomial
pub fn commit_poly<G: KimchiCurve>(
    srs: &SRS<G>,
    poly: &DensePolynomial<G::ScalarField>,
) -> Commitment<G> {
    Commitment {
        cm: srs.commit_non_hiding(poly, 1).chunks[0],
    }
}

/// Compute the commitment to the polynomial `P` of same degree as `srs`
/// such that `P(ω_i) = sparse_data[i]` for all `ì` in `indexes` and `P(ω_i) = 0`
/// for any other `ω_i` of the domain of the same size as `srs`.
/// This commitment is computed in a sparse way through the sum of `sparse_data[i] × [L_i]`
/// for all i in `indexes` and `[L_i]` the commitment to the i-th Lagrange polynomial
/// of same degree as `srs`.
pub fn commit_sparse<G: KimchiCurve>(
    srs: &SRS<G>,
    sparse_data: &[G::ScalarField],
    indexes: &[u64],
) -> Commitment<G> {
    if sparse_data.len() != indexes.len() {
        panic!(
            "commitment::commit_sparse: size mismatch (sparse_data: {}, indexes: {})",
            sparse_data.len(),
            indexes.len()
        )
    };
    let basis = get_lagrange_basis(srs);
    let basis: Vec<G> = indexes.iter().map(|&i| basis[i as usize]).collect();
    Commitment {
        cm: G::Group::msm(&basis, sparse_data).unwrap().into(),
    }
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
    let combined_data_commitment = utils::aggregate_commitments(alpha, commitments);
    (combined_data_commitment, alpha)
}

/// A commitment that represent a whole data
/// TODO: for now, we consider 1 commitment = 1 contract = 1 data
/// This type may be redundant with other types in Proof-systems
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Commitment<G: KimchiCurve> {
    pub cm: G,
}

impl<G: KimchiCurve> From<G> for Commitment<G> {
    fn from(cm: G) -> Self {
        Self { cm }
    }
}

impl<G: KimchiCurve> Commitment<G> {
    /// Commit a `data` of length smaller than `SRS_SIZE`
    /// If greater data is provided, anything above `SRS_SIZE` is ignored
    pub fn from_data(srs: &SRS<G>, data: &[G::ScalarField]) -> Commitment<G> {
        Commitment {
            cm: commit_to_field_elems::<G>(srs, data)[0],
        }
    }

    /// TODO: This only handle the single commitment version for now
    /// This function update the given commitment based on the given diff. The
    /// returned commitment correspond to the data for the given commitment updated
    /// according to the diff.
    /// This function is tested in storage.rs
    pub fn update(&self, srs: &SRS<G>, diff: Diff<G::ScalarField>) -> Commitment<G> {
        // TODO: precompute this, or cache it & compute it in a lazy way ; it feels like it’s already cached but I’m not sure
        let cm_diff = commit_sparse(srs, &diff.diff_values, &diff.addresses);
        Commitment {
            cm: self.cm.add(cm_diff.cm).into(),
        }
    }
}
