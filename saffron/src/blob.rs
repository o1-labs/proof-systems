use crate::{
    commitment::commit_to_field_elems,
    diff::Diff,
    encoding::{self, decode_from_field_elements, decode_into, encode_for_domain},
    Curve, ProjectiveCurve, ScalarField, SRS_SIZE,
};
use ark_ec::{AffineRepr, VariableBaseMSM};
use ark_ff::{PrimeField, Zero};
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use o1_utils::FieldHelpers;
use poly_commitment::{ipa::SRS, SRS as _};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use tracing::{debug, instrument};

/// A `FieldBlob<F>` is what Storage Provider stores per user's
/// contract: a list of `SRS_SIZE * num_chunks` field elements, where
/// num_chunks is how much the client allocated.
///
/// It can be seen as the encoding of a `Vec<u8>`, where each field
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
        diff: &Diff<ScalarField>,
    ) {
        assert!(diff.addresses.len() == diff.new_values.len());

        let lagrange_basis = srs
            .get_lagrange_basis(*domain)
            .iter()
            .map(|x| x.chunks[0])
            .collect::<Vec<_>>();
        let basis = lagrange_basis.as_slice();

        let address_basis: Vec<_> = diff
            .addresses
            .par_iter()
            .map(|idx| basis[*idx as usize])
            .collect();

        // Old values at `addresses`
        let old_values_at_addr: Vec<_> = diff
            .addresses
            .iter()
            .map(|idx| self.data[diff.region as usize * SRS_SIZE + *idx as usize])
            .collect();

        for (idx, value) in diff.addresses.iter().zip(diff.new_values.iter()) {
            self.data[SRS_SIZE * diff.region as usize + *idx as usize] = *value;
        }

        // Lagrange commitment to the (new values-old values) at `addresses`
        let delta_data_commitment_at_addr = ProjectiveCurve::msm(
            address_basis.as_slice(),
            old_values_at_addr
                .iter()
                .zip(diff.new_values.iter())
                .map(|(old, new)| new - old)
                .collect::<Vec<_>>()
                .as_slice(),
        )
        .unwrap();

        let new_commitment =
            (self.commitments[diff.region as usize] + delta_data_commitment_at_addr).into();

        self.commitments[diff.region as usize] = new_commitment;
    }

    pub fn from_data(srs: &SRS<Curve>, data: &[ScalarField]) -> FieldBlob {
        let commitments = commit_to_field_elems(srs, data);
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
        let field_elements: Vec<ScalarField> = encode_for_domain(domain.size(), bytes)
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

    /// Returns the byte representation of the `FieldBlob`.
    #[instrument(skip_all, level = "debug")]
    pub fn into_bytes(blob: FieldBlob) -> Vec<u8> {
        decode_from_field_elements(blob.data)
    }
}

#[cfg(test)]
mod tests {
    use crate::env;

    use super::*;

    use crate::{diff::tests::*, utils::test_utils::*, Curve, ScalarField};
    use ark_ec::AffineRepr;
    use ark_ff::Zero;
    use ark_poly::Radix2EvaluationDomain;
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
        {
            let blob = FieldBlob::from_bytes::<_>(&SRS, *DOMAIN, &xs);
            let bytes = rmp_serde::to_vec(&blob).unwrap();
            let a = rmp_serde::from_slice(&bytes).unwrap();
            // check that ark-serialize is behaving as expected
            prop_assert_eq!(blob.clone(), a);
            let ys = FieldBlob::into_bytes(blob);
            // check that we get the byte blob back again
            prop_assert_eq!(xs,ys);
        }
    }

    proptest! {
    #![proptest_config(ProptestConfig::with_cases(10))]
    #[test]
    fn test_user_and_storage_provider_commitments_equal(UserData(xs) in UserData::arbitrary())
      { let elems: Vec<_> = encode_for_domain(DOMAIN.size(), &xs).into_iter().flatten().collect();
        let user_commitments: Vec<_> = commit_to_field_elems(&SRS, &elems);
        let blob = FieldBlob::from_bytes::<_>(&SRS, *DOMAIN, &xs);
        prop_assert_eq!(user_commitments, blob.commitments);
      }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(10))]
        #[test]

        fn test_allow_legal_updates((UserData(xs), UserData(ys)) in
            (UserData::arbitrary_with(DataSize::Medium).prop_flat_map(random_diff))
        ) {
            // start with some random user data
            let mut xs_blob = FieldBlob::from_bytes::<_>(&SRS, *DOMAIN, &xs);
            let diffs = Diff::<ScalarField>::create_from_bytes(&*DOMAIN, &xs, &ys).unwrap();

            // check that the user and SP agree on the data
            let user_commitment: Vec<_> = {
                let elems: Vec<_> = encode_for_domain(DOMAIN.size(), &xs).into_iter().flatten().collect();
                commit_to_field_elems(&SRS, &elems)

            };
            prop_assert_eq!(user_commitment.clone(), xs_blob.commitments.clone());

            // Update the blob with the diff and check the user can match the commitment
            for diff in diffs.iter() {
                xs_blob.apply_diff(&SRS, &DOMAIN, diff);
            }
            
            let ys_blob = FieldBlob::from_bytes::<_>(&SRS, *DOMAIN, &ys);

            prop_assert_eq!(xs_blob.data, ys_blob.data);
            prop_assert_eq!(xs_blob.commitments, ys_blob.commitments);
        }

    }
}
