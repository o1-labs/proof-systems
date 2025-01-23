use ark_poly::{Evaluations, Radix2EvaluationDomain as D};
use poly_commitment::{commitment::CommitmentCurve, ipa::SRS, PolyComm, SRS as _};
use rayon::prelude::*;

use crate::blob::FieldBlob;

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

pub fn commit_to_blob<G: CommitmentCurve>(
    srs: &SRS<G>,
    blob: FieldBlob<G::ScalarField>,
) -> Vec<PolyComm<G>> {
    let num_chunks = 1;
    blob.data
        .par_iter()
        .map(|p| srs.commit_non_hiding(p, num_chunks))
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::utils::encode_for_domain;

    use super::*;
    use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
    use mina_curves::pasta::{Fp, Vesta};
    use o1_utils::FieldHelpers;
    use once_cell::sync::Lazy;
    use proptest::prelude::*;

    const SRS_SIZE: usize = 1 << 16;

    static SRS: Lazy<SRS<Vesta>> = Lazy::new(|| SRS::create(SRS_SIZE));

    static DOMAIN: Lazy<Radix2EvaluationDomain<Fp>> =
        Lazy::new(|| Radix2EvaluationDomain::new(SRS_SIZE).unwrap());

    proptest! {
    #![proptest_config(ProptestConfig::with_cases(10))]
    #[test]
        fn test_user_and_storage_provider_commitments_equal(xs in prop::collection::vec(any::<u8>(), 0..=2 * Fp::size_in_bytes() * DOMAIN.size())
        )
          { let elems = encode_for_domain(&*DOMAIN, &xs);
            let user_commitment = commit_to_field_elems(&*SRS, *DOMAIN, elems);
            let blob = FieldBlob::<Fp>::encode(*DOMAIN, &xs);
            let storeage_provider_commitment = commit_to_blob(&*SRS, blob);
            prop_assert_eq!(user_commitment, storeage_provider_commitment);
          }
        }
}
