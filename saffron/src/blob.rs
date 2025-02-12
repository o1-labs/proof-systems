use crate::{
    commitment::Commitment,
    diff::Diff,
    query::IndexQuery,
    utils::{decode_into, encode_for_domain},
};
use ark_ff::PrimeField;
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

// A FieldBlob<F> represents the encoding of a Vec<u8> as a list of polynomials over F,
// where F is a prime field. The polyonomials are represented in the monomial basis.
#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(bound = "G::ScalarField : CanonicalDeserialize + CanonicalSerialize")]
pub struct FieldBlob<G: CommitmentCurve> {
    pub n_bytes: usize,
    pub domain_size: usize,
    pub commitment: Commitment<G>,
    #[serde_as(as = "Vec<o1_utils::serialization::SerdeAs>")]
    pub chunks: Vec<DensePolynomial<G::ScalarField>>,
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

impl<G: KimchiCurve> FieldBlob<G> {
    pub fn n_chunks(&self) -> usize {
        self.chunks.len()
    }

    #[instrument(skip_all, level = "debug")]
    pub fn encode<
        D: EvaluationDomain<G::ScalarField>,
        EFqSponge: FqSponge<G::BaseField, G, G::ScalarField>,
    >(
        srs: &SRS<G>,
        domain: D,
        bytes: &[u8],
    ) -> FieldBlob<G> {
        let field_elements = encode_for_domain(&domain, bytes);
        let domain_size = domain.size();

        let chunks: Vec<DensePolynomial<G::ScalarField>> = debug_span!("fft").in_scope(|| {
            field_elements
                .par_iter()
                .map(|chunk| Evaluations::from_vec_and_domain(chunk.to_vec(), domain).interpolate())
                .collect()
        });
        let commitment = {
            let chunks = commit_to_blob_data(srs, &chunks);
            let mut sponge = EFqSponge::new(G::other_curve_sponge_params());
            Commitment::from_chunks(chunks, &mut sponge)
        };

        debug!(
            "Encoded {:.2} MB into {} polynomials",
            bytes.len() as f32 / 1_000_000.0,
            chunks.len()
        );

        FieldBlob {
            n_bytes: bytes.len(),
            domain_size,
            commitment,
            chunks,
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

        for p in blob.chunks {
            let evals = p.evaluate_over_domain(domain).evals;
            for x in evals {
                decode_into(&mut buffer, x);
                bytes.extend_from_slice(&buffer[(m - n)..m]);
            }
        }

        bytes.truncate(blob.n_bytes);
        bytes
    }

    pub fn update<EFqSponge: FqSponge<G::BaseField, G, G::ScalarField>>(
        &mut self,
        srs: &SRS<G>,
        domain: &Radix2EvaluationDomain<G::ScalarField>,
        diff: Diff<G::ScalarField>,
    ) {
        let diff_evaluations = diff.as_evaluations(domain);
        let commitment = {
            let commitment_diffs = diff_evaluations
                .par_iter()
                .map(|evals| srs.commit_evaluations_non_hiding(*domain, evals))
                .collect::<Vec<_>>();
            let mut sponge = EFqSponge::new(G::other_curve_sponge_params());
            self.commitment.update(commitment_diffs, &mut sponge)
        };
        let chunks: Vec<DensePolynomial<G::ScalarField>> = diff_evaluations
            .into_par_iter()
            .zip(self.chunks.par_iter())
            .map(|(evals, p)| {
                let d_p: DensePolynomial<G::ScalarField> = evals.interpolate();
                p + &d_p
            })
            .collect();
        self.commitment = commitment;
        self.chunks = chunks;
        self.n_bytes = diff.new_byte_len;
    }

    pub fn query(
        &self,
        domain: Radix2EvaluationDomain<G::ScalarField>,
        indices: IndexQuery,
    ) -> IndexQueryResult<G::ScalarField> {
        IndexQueryResult {
            chunks: indices
                .chunks
                .into_iter()
                .enumerate()
                .map(|(poly_index, eval_indices)| {
                    let evals = self.chunks[poly_index].clone().evaluate_over_domain(domain);
                    eval_indices
                        .into_iter()
                        .map(move |eval_index| (eval_index, evals[eval_index]))
                        .collect::<Vec<_>>()
                })
                .collect(),
        }
    }
}

pub struct IndexQueryResult<F> {
    pub chunks: Vec<Vec<(usize, F)>>,
}

impl<F: PrimeField> IndexQueryResult<F> {
    pub fn as_evaluations(
        &self,
        domain: Radix2EvaluationDomain<F>,
    ) -> Vec<Evaluations<F, Radix2EvaluationDomain<F>>> {
        self.chunks
            .par_iter()
            .map(|chunk| {
                let mut evals = vec![F::zero(); domain.size()];
                chunk.iter().for_each(|(j, val)| {
                    evals[*j] = *val;
                });
                Evaluations::from_vec_and_domain(evals, domain)
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use crate::{commitment::commit_to_field_elems, env};

    use super::*;
    use crate::{diff::tests::*, utils::test_utils::*};
    use ark_ec::AffineRepr;
    use ark_ff::Zero;
    use ark_poly::Radix2EvaluationDomain;
    use mina_curves::pasta::{Fp, Vesta, VestaParameters};
    use mina_poseidon::{constants::PlonkSpongeConstantsKimchi, sponge::DefaultFqSponge};
    use once_cell::sync::Lazy;
    use proptest::prelude::*;

    type VestaFqSponge = DefaultFqSponge<VestaParameters, PlonkSpongeConstantsKimchi>;

    static SRS: Lazy<SRS<Vesta>> = Lazy::new(|| {
        if let Ok(srs) = std::env::var("SRS_FILEPATH") {
            env::get_srs_from_cache(srs)
        } else {
            SRS::create(1 << 16)
        }
    });

    static DOMAIN: Lazy<Radix2EvaluationDomain<Fp>> =
        Lazy::new(|| Radix2EvaluationDomain::new(SRS.size()).unwrap());

    // check that Vec<u8> -> FieldBlob<Fp> -> Vec<u8> is the identity function
    proptest! {
    #![proptest_config(ProptestConfig::with_cases(20))]
    #[test]
    fn test_round_trip_blob_encoding(UserData(xs) in UserData::arbitrary())
      { let blob = FieldBlob::<Vesta>::encode::<_, VestaFqSponge>(&*SRS, *DOMAIN, &xs);
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
    fn test_user_and_storage_provider_commitments_equal(UserData(xs) in UserData::arbitrary())
      { let elems = encode_for_domain(&*DOMAIN, &xs);
        let user_commitments = commit_to_field_elems::<_, VestaFqSponge>(&*SRS, *DOMAIN, elems);
        let blob = FieldBlob::<Vesta>::encode::<_, VestaFqSponge>(&*SRS, *DOMAIN, &xs);
        prop_assert_eq!(user_commitments, blob.commitment);
      }
    }

    fn encode_to_chunk_size(xs: &[u8], chunk_size: usize) -> FieldBlob<Vesta> {
        let mut blob = FieldBlob::<Vesta>::encode::<_, VestaFqSponge>(&*SRS, *DOMAIN, xs);
        assert!(blob.chunks.len() <= chunk_size);
        {
            let pad = DensePolynomial::zero();
            blob.chunks.resize(chunk_size, pad);
        }
        {
            let pad = PolyComm::new(vec![Vesta::zero()]);
            let mut commitments = blob.commitment.chunks.clone();
            commitments.resize(chunk_size, pad);
            let mut sponge = VestaFqSponge::new(Vesta::other_curve_sponge_params());
            blob.commitment = Commitment::from_chunks(commitments, &mut sponge);
        }
        blob
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(20))]
        #[test]

        fn test_allow_legal_updates((UserData(xs), UserData(ys)) in
            (UserData::arbitrary().prop_flat_map(random_diff))
        ) {
            // start with some random user data
            let mut xs_blob = FieldBlob::<Vesta>::encode::<_, VestaFqSponge>(&*SRS, *DOMAIN, &xs);
            let diff = Diff::<Fp>::create(&*DOMAIN, &xs, &ys).unwrap();
            xs_blob.update::<VestaFqSponge>(&*SRS, &*DOMAIN, diff.clone());

            // check that the user and SP agree on the new data
            let user_commitment = {
                let elems = encode_for_domain(&*DOMAIN, &xs);
                let commitment = commit_to_field_elems::<Vesta, VestaFqSponge>(&*SRS, *DOMAIN, elems);

                let commitment_diffs = diff.as_evaluations(&*DOMAIN)
                    .par_iter()
                    .map(|evals| SRS.commit_evaluations_non_hiding(*DOMAIN, evals))
                    .collect::<Vec<_>>();

                let mut sponge = VestaFqSponge::new(Vesta::other_curve_sponge_params());
                commitment.update(commitment_diffs, &mut sponge)

            };

            let ys_blob = encode_to_chunk_size(&ys, xs_blob.chunks.len());
            prop_assert_eq!(user_commitment.clone(), ys_blob.commitment.clone());

            // the updated blob should be the same as if we just start with the new data
            prop_assert_eq!(xs_blob, ys_blob)
        }

    }
}
