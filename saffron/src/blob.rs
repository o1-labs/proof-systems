use crate::utils::{decode_into, encode_for_domain};
use ark_ff::PrimeField;
use ark_poly::{univariate::DensePolynomial, EvaluationDomain, Evaluations};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use o1_utils::FieldHelpers;
use poly_commitment::{commitment::CommitmentCurve, ipa::SRS, PolyComm, SRS as _};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use tracing::{debug, instrument};

// A FieldBlob<F> represents the encoding of a Vec<u8> as a list of polynomials over F,
// where F is a prime field. The polyonomials are represented in the monomial basis.
#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(bound = "G::ScalarField : CanonicalDeserialize + CanonicalSerialize")]
pub struct FieldBlob<G: CommitmentCurve> {
    pub n_bytes: usize,
    pub domain_size: usize,
    pub commitments: Vec<PolyComm<G>>,
    #[serde_as(as = "Vec<o1_utils::serialization::SerdeAs>")]
    pub data: Vec<DensePolynomial<G::ScalarField>>,
}

#[instrument(skip_all, level = "debug")]
fn commit_to_blob_data<G: CommitmentCurve>(
    srs: &SRS<G>,
    data: &[DensePolynomial<G::ScalarField>],
) -> Vec<PolyComm<G>> {
    let num_chunks = 1;
    data.par_iter()
        .map(|p| srs.commit_non_hiding(p, num_chunks))
        .collect()
}

impl<G: CommitmentCurve> FieldBlob<G> {
    #[instrument(skip_all, level = "debug")]
    pub fn encode<D: EvaluationDomain<G::ScalarField>>(
        srs: &SRS<G>,
        domain: D,
        bytes: &[u8],
    ) -> FieldBlob<G> {
        let field_elements = encode_for_domain(&domain, bytes);
        let domain_size = domain.size();

        let data: Vec<DensePolynomial<G::ScalarField>> = field_elements
            .par_iter()
            .map(|chunk| Evaluations::from_vec_and_domain(chunk.to_vec(), domain).interpolate())
            .collect();

        let commitments = commit_to_blob_data(srs, &data);

        debug!(
            "Encoded {} bytes into {} polynomials",
            bytes.len(),
            data.len()
        );

        FieldBlob {
            n_bytes: bytes.len(),
            domain_size,
            commitments,
            data,
        }
    }

    #[instrument(skip_all, level = "debug")]
    pub fn decode<D: EvaluationDomain<G::ScalarField>>(domain: D, blob: FieldBlob<G>) -> Vec<u8> {
        // TODO: find an Error type and use Result
        if domain.size() != blob.domain_size {
            panic!(
                "Domain size mismatch, got {}, expected {}",
                blob.domain_size,
                domain.size()
            );
        }
        let n = (G::ScalarField::MODULUS_BIT_SIZE / 8) as usize;
        let m = G::ScalarField::size_in_bytes();
        let mut bytes = Vec::with_capacity(blob.n_bytes);
        let mut buffer = vec![0u8; m];

        for p in blob.data {
            let evals = p.evaluate_over_domain(domain).evals;
            for x in evals {
                decode_into(&mut buffer, x);
                bytes.extend_from_slice(&buffer[(m - n)..m]);
            }
        }

        bytes.truncate(blob.n_bytes);
        bytes
    }
}

#[cfg(test)]
mod tests {
    use crate::commitment::commit_to_field_elems;

    use super::*;
    use ark_poly::Radix2EvaluationDomain;
    use mina_curves::pasta::{Fp, Vesta};
    use once_cell::sync::Lazy;
    use proptest::prelude::*;

    const SRS_SIZE: usize = 1 << 16;

    static SRS: Lazy<SRS<Vesta>> = Lazy::new(|| SRS::create(SRS_SIZE));

    static DOMAIN: Lazy<Radix2EvaluationDomain<Fp>> =
        Lazy::new(|| Radix2EvaluationDomain::new(SRS_SIZE).unwrap());

    // check that Vec<u8> -> FieldBlob<Fp> -> Vec<u8> is the identity function
    proptest! {
    #![proptest_config(ProptestConfig::with_cases(20))]
    #[test]
    fn test_round_trip_blob_encoding( xs in prop::collection::vec(any::<u8>(), 0..=2 * Fp::size_in_bytes() * DOMAIN.size()))
      { let blob = FieldBlob::<Vesta>::encode(&*SRS, *DOMAIN, &xs);
        let bytes = rmp_serde::to_vec(&blob).unwrap();
        let a = rmp_serde::from_slice(&bytes).unwrap();
        // check that ark-serialize is behaving as expected
        prop_assert_eq!(blob.clone(), a);
        let ys = FieldBlob::<Vesta>::decode(*DOMAIN, blob);
        // check that we get the byte blob back again
        prop_assert_eq!(xs,ys);
      }
    }

    proptest! {
    #![proptest_config(ProptestConfig::with_cases(10))]
    #[test]
        fn test_user_and_storage_provider_commitments_equal(xs in prop::collection::vec(any::<u8>(), 0..=2 * Fp::size_in_bytes() * DOMAIN.size())
        )
          { let elems = encode_for_domain(&*DOMAIN, &xs);
            let user_commitments = commit_to_field_elems(&*SRS, *DOMAIN, elems);
            let blob = FieldBlob::<Vesta>::encode(&*SRS, *DOMAIN, &xs);
            prop_assert_eq!(user_commitments, blob.commitments);
          }
        }
}
