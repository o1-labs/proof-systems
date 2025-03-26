use crate::{
    commitment::CommittedData,
    diff::Diff,
    utils::{decode_into, encode_for_domain},
    BaseField, Curve, CurveFqSponge, ProjectiveCurve, ScalarField, SRS_SIZE,
};
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{One, PrimeField, Zero};
use ark_poly::{
    univariate::DensePolynomial, EvaluationDomain, Evaluations, Radix2EvaluationDomain,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use kimchi::curve::KimchiCurve;
use mina_poseidon::FqSponge;
use o1_utils::FieldHelpers;
use poly_commitment::{commitment::CommitmentCurve, ipa::SRS, PolyComm, SRS as _};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use tracing::{debug, debug_span, instrument};

/// A FieldBlob<F> is what Storage Provider stores per user's
/// contract: a list of SRS_SIZE * chunk_size field elements, where
/// chunk_size is how much the client allocated.
///
/// It can be seen as the encoding of a Vec<u8>, where each field
/// element contains 31 bytes.
#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(bound = "ScalarField : CanonicalDeserialize + CanonicalSerialize")]
pub struct FieldBlob {
    #[serde_as(as = "Vec<o1_utils::serialization::SerdeAs>")]
    pub data: Vec<ScalarField>,
    #[serde_as(as = "Vec<o1_utils::serialization::SerdeAs>")]
    pub commitments: Vec<Curve>,
}

#[instrument(skip_all, level = "debug")]
fn commit_to_blob_data<G: CommitmentCurve>(
    srs: &SRS<Curve>,
    data: &[DensePolynomial<ScalarField>],
) -> Vec<PolyComm<Curve>> {
    let num_chunks = 1;
    data.par_iter()
        .map(|p| srs.commit_non_hiding(p, num_chunks))
        .collect()
}

impl FieldBlob {
    pub fn alloc_empty(num_chunks: usize) -> FieldBlob {
        let data = vec![ScalarField::zero(); num_chunks * SRS_SIZE];

        let commitments = vec![Curve::zero(); num_chunks];

        FieldBlob { data, commitments }
    }

    pub fn apply_diff(
        &mut self,
        srs: &SRS<Curve>,
        domain: &Radix2EvaluationDomain<ScalarField>,
        diff: Diff<ScalarField>,
    ) {
        assert!(diff.addresses.len() == diff.new_values.len());

        let basis = srs
            .get_lagrange_basis(*domain)
            .iter()
            .map(|x| x.chunks[0])
            .collect::<Vec<_>>();
        let basis = basis.as_slice();

        let address_basis: Vec<_> = diff
            .addresses
            .par_iter()
            .map(|idx| basis[*idx as usize])
            .collect();

        let computed_query_commitment = address_basis
            .par_iter()
            .map(|x| x.into_group())
            .reduce(|| Curve::zero().into_group(), |x, y| x + y);

        for (idx, value) in diff.addresses.iter().zip(diff.new_values.iter()) {
            self.data[SRS_SIZE * diff.region as usize + *idx as usize] = *value;
        }

        // Old values at `addresses`
        let old_values: Vec<_> = diff
            .addresses
            .iter()
            .map(|idx| self.data[diff.region as usize * SRS_SIZE + *idx as usize])
            .collect();

        // Lagrange commitment to them.
        let old_data_commitment =
            ProjectiveCurve::msm(address_basis.as_slice(), old_values.as_slice()).unwrap();

        // Lagrange commitment to the new values at `addresses`
        let new_data_commitment =
            ProjectiveCurve::msm(address_basis.as_slice(), diff.new_values.as_slice()).unwrap();

        let new_commitment = (self.commitments[diff.region as usize] + new_data_commitment
            - old_data_commitment)
            .into();

        self.commitments[diff.region as usize] = new_commitment;
    }

    pub fn from_data(srs: &SRS<Curve>, data: &[ScalarField]) -> FieldBlob {
        let basis = srs
            .get_lagrange_basis_from_domain_size(SRS_SIZE)
            .iter()
            .map(|x| x.chunks[0])
            .collect::<Vec<_>>();

        let commitments_projective = (0..data.len() / SRS_SIZE)
            .into_par_iter()
            .map(|idx| {
                ProjectiveCurve::msm(&basis, &data[SRS_SIZE * idx..SRS_SIZE * (idx + 1)]).unwrap()
                    + srs.h
            })
            .collect::<Vec<_>>();

        let commitments = ProjectiveCurve::normalize_batch(commitments_projective.as_slice());

        FieldBlob {
            commitments,
            data: Vec::from(data),
        }
    }

    #[instrument(skip_all, level = "debug")]
    pub fn from_bytes<D: EvaluationDomain<ScalarField>>(
        srs: &SRS<Curve>,
        domain: D,
        bytes: &[u8],
    ) -> FieldBlob {
        let field_elements: Vec<ScalarField> = encode_for_domain(&domain, bytes)
            .into_iter()
            .flatten()
            .collect();

        let res = Self::from_data(srs, field_elements.as_slice());

        debug!(
            "Encoded {:.2} MB into {} polynomials",
            bytes.len() as f32 / 1_000_000.0,
            res.commitments.len()
        );

        res
    }

    #[instrument(skip_all, level = "debug")]
    pub fn into_bytes<D: EvaluationDomain<ScalarField>>(domain: D, blob: FieldBlob) -> Vec<u8> {
        // TODO: find an Error type and use Result
        if domain.size() != SRS_SIZE {
            panic!(
                "Domain size mismatch, got {}, expected {}",
                SRS_SIZE,
                domain.size()
            );
        }
        // n < m
        // How many bytes fit into the field
        let n = (ScalarField::MODULUS_BIT_SIZE / 8) as usize;
        // How many bytes are necessary to fit a field element
        let m = ScalarField::size_in_bytes();

        let intended_vec_len = n * blob.commitments.len() * SRS_SIZE;
        let mut bytes = Vec::with_capacity(intended_vec_len);
        let mut buffer = vec![0u8; m];

        for x in blob.data {
            decode_into(&mut buffer, x);
            bytes.extend_from_slice(&buffer[(m - n)..m]);
        }

        // bytes.truncate(blob.n_bytes);
        assert!(bytes.len() == intended_vec_len);

        bytes
    }
}

#[cfg(test)]
mod tests {
    use crate::{commitment::commit_to_field_elems, env};

    use super::*;
    use crate::{
        diff::tests::*, utils::test_utils::*, Curve, CurveFqSponge, CurveParameters, ScalarField,
    };
    use ark_ec::AffineRepr;
    use ark_ff::Zero;
    use ark_poly::Radix2EvaluationDomain;
    use mina_poseidon::{constants::PlonkSpongeConstantsKimchi, sponge::DefaultFqSponge};
    use once_cell::sync::Lazy;
    use proptest::prelude::*;

    static SRS: Lazy<SRS<Curve>> = Lazy::new(|| {
        if let Ok(srs) = std::env::var("SRS_FILEPATH") {
            env::get_srs_from_cache(srs)
        } else {
            SRS::create(1 << 16)
        }
    });

    static DOMAIN: Lazy<Radix2EvaluationDomain<ScalarField>> =
        Lazy::new(|| Radix2EvaluationDomain::new(SRS.size()).unwrap());

    // check that Vec<u8> -> FieldBlob<ScalarField> -> Vec<u8> is the identity function
    proptest! {
    #![proptest_config(ProptestConfig::with_cases(20))]
    #[test]
    fn test_round_trip_blob_encoding(UserData(xs) in UserData::arbitrary())
      { let blob = FieldBlob::<Curve>::from_bytes::<_, CurveFqSponge>(&*SRS, *DOMAIN, &xs);
        let bytes = rmp_serde::to_vec(&blob).unwrap();
        let a = rmp_serde::from_slice(&bytes).unwrap();
        // check that ark-serialize is behaving as expected
        prop_assert_eq!(blob.clone(), a);
        let ys = FieldBlob::<Curve>::into_bytes(*DOMAIN, blob);
        // check that we get the byte blob back again
        prop_assert_eq!(xs,ys);
      }
    }

    proptest! {
    #![proptest_config(ProptestConfig::with_cases(10))]
    #[test]
    fn test_user_and_storage_provider_commitments_equal(UserData(xs) in UserData::arbitrary())
      { let elems = encode_for_domain(&*DOMAIN, &xs);
        let user_commitments = commit_to_field_elems::<_, CurveFqSponge>(&*SRS, *DOMAIN, elems);
        let blob = FieldBlob::<Curve>::from_bytes::<_, CurveFqSponge>(&*SRS, *DOMAIN, &xs);
        prop_assert_eq!(user_commitments, blob.commitments);
      }
    }

    fn encode_to_chunk_size(xs: &[u8], chunk_size: usize) -> FieldBlob {
        let mut blob = FieldBlob::<Curve>::from_bytes::<_, CurveFqSponge>(&*SRS, *DOMAIN, xs);
        assert!(blob.data.len() <= chunk_size);
        {
            let pad = DensePolynomial::zero();
            blob.data.resize(chunk_size, pad);
        }
        {
            let pad = PolyComm::new(vec![Curve::zero()]);
            let mut commitments = blob.commitments.chunks.clone();
            commitments.resize(chunk_size, pad);
            let mut sponge = CurveFqSponge::new(Curve::other_curve_sponge_params());
            blob.commitments = CommittedData::from_chunks(commitments, &mut sponge);
        }
        blob
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(10))]
        #[test]

        fn test_allow_legal_updates((UserData(xs), UserData(ys)) in
            (UserData::arbitrary_with(DataSize::Medium).prop_flat_map(random_diff))
        ) {
            // start with some random user data
            let mut xs_blob = FieldBlob::<Curve>::from_bytes::<_, CurveFqSponge>(&*SRS, *DOMAIN, &xs);
            let diff = Diff::<ScalarField>::create(&*DOMAIN, &xs, &ys).unwrap();

            // check that the user and SP agree on the data
            let user_commitment = {
                let elems = encode_for_domain(&*DOMAIN, &xs);
                commit_to_field_elems::<Curve, CurveFqSponge>(&*SRS, *DOMAIN, elems)

            };
            prop_assert_eq!(user_commitment.clone(), xs_blob.commitments.clone());

            // Update the blob with the diff and check the user can match the commitment
            xs_blob.apply_diff::<CurveFqSponge>(&*SRS, &*DOMAIN, diff.clone());

            let updated_user_commitment = {
                let commitment_diffs = diff.as_evaluations(&*DOMAIN)
                    .par_iter()
                    .map(|evals| SRS.commit_evaluations_non_hiding(*DOMAIN, evals))
                    .collect::<Vec<_>>();

                let mut sponge = CurveFqSponge::new(Curve::other_curve_sponge_params());
                user_commitment.update(commitment_diffs, &mut sponge)
            };
            prop_assert_eq!(updated_user_commitment, xs_blob.commitments.clone());

            // the updated blob should be the same as if we just start with the new data (with appropriate padding)
            let ys_blob = encode_to_chunk_size(&ys, xs_blob.data.len());
            prop_assert_eq!(xs_blob, ys_blob)
        }

    }
}
