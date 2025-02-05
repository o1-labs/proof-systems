use std::collections::HashMap;

use crate::{
    commitment::fold_commitments,
    utils::{decode_into, encode_for_domain},
};
use ark_ec::AffineRepr;
use ark_ff::{PrimeField, Zero};
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
use std::ops::Add;
use tracing::{debug_span, info, instrument};

// A FieldBlob<F> represents the encoding of a Vec<u8> as a list of polynomials over F,
// where F is a prime field. The polyonomials are represented in the monomial basis.
#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(bound = "G::ScalarField : CanonicalDeserialize + CanonicalSerialize")]
pub struct FieldBlob<G: CommitmentCurve> {
    pub n_bytes: usize,
    pub domain_size: usize,
    pub commitments: Vec<PolyComm<G>>,
    pub folded_commitment: PolyComm<G>,
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub alpha: G::ScalarField,
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

impl<G: KimchiCurve> FieldBlob<G> {
    #[instrument(skip_all, level = "debug")]
    pub fn encode<
        D: EvaluationDomain<G::ScalarField>,
        EFqSponge: Clone + FqSponge<G::BaseField, G, G::ScalarField>,
    >(
        srs: &SRS<G>,
        domain: D,
        bytes: &[u8],
    ) -> FieldBlob<G> {
        let field_elements = encode_for_domain(&domain, bytes);
        let domain_size = domain.size();

        let data: Vec<DensePolynomial<G::ScalarField>> = debug_span!("fft").in_scope(|| {
            field_elements
                .par_iter()
                .map(|chunk| Evaluations::from_vec_and_domain(chunk.to_vec(), domain).interpolate())
                .collect()
        });

        let commitments = commit_to_blob_data(srs, &data);

        let (folded_commitment, alpha) = {
            let mut sponge = EFqSponge::new(G::other_curve_sponge_params());
            fold_commitments(&mut sponge, &commitments)
        };

        info!(
            "Encoded {:.2} MB into {} polynomials",
            bytes.len() as f32 / 1_000_000.0,
            data.len()
        );

        FieldBlob {
            n_bytes: bytes.len(),
            domain_size,
            commitments,
            folded_commitment,
            alpha,
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

    #[instrument(skip_all, level = "debug")]
    pub fn update<EFqSponge: Clone + FqSponge<G::BaseField, G, G::ScalarField>>(
        &mut self,
        srs: &SRS<G>,
        domain: &Radix2EvaluationDomain<G::ScalarField>,
        diffs: Vec<HashMap<usize, G::ScalarField>>,
    ) {
        let updates: Vec<(usize, PolyComm<G>, DensePolynomial<G::ScalarField>)> = diffs
            .into_par_iter()
            .enumerate()
            .map(|(index, diff)| {
                let d_p = {
                    let evals = (0..domain.size())
                        .map(|i| {
                            diff.get(&i)
                                .copied()
                                .unwrap_or(<G as AffineRepr>::ScalarField::zero())
                        })
                        .collect();
                    Evaluations::from_vec_and_domain(evals, *domain).interpolate()
                };
                let d_commitment = srs.commit_non_hiding(&d_p, 1);
                (index, d_commitment, d_p)
            })
            .collect();
        for (index, d_commitment, d_p) in updates {
            self.commitments[index] = self.commitments[index].add(&d_commitment);
            self.data[index] = (&self.data[index]).add(&d_p);
        }

        let (folded_commitment, alpha) = {
            let mut sponge = EFqSponge::new(G::other_curve_sponge_params());
            fold_commitments(&mut sponge, &self.commitments)
        };

        self.alpha = alpha;
        self.folded_commitment = folded_commitment;
    }
}

#[cfg(test)]
mod tests {
    use crate::{commitment::commit_to_field_elems, env, utils::make_diff};

    use super::*;
    use crate::utils::test_utils::*;
    use ark_poly::Radix2EvaluationDomain;
    use mina_curves::pasta::{Fp, Vesta, VestaParameters};
    use mina_poseidon::{constants::PlonkSpongeConstantsKimchi, sponge::DefaultFqSponge};
    use once_cell::sync::Lazy;
    use proptest::prelude::*;
    use rand::Rng;

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
      { let blob = FieldBlob::<Vesta>::encode::<_, DefaultFqSponge<VestaParameters, PlonkSpongeConstantsKimchi>>(&*SRS, *DOMAIN, &xs);
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
            let user_commitments = commit_to_field_elems(&*SRS, *DOMAIN, elems);
            let blob = FieldBlob::<Vesta>::encode::<_, DefaultFqSponge<VestaParameters, PlonkSpongeConstantsKimchi>>(&*SRS, *DOMAIN, &xs);
            prop_assert_eq!(user_commitments, blob.commitments);
          }
        }

    fn random_perturbation(threshold: f64, data: &[u8]) -> Vec<u8> {
        let mut rng = rand::thread_rng();
        data.iter()
            .map(|b| {
                let n = rng.gen::<f64>();
                if n < threshold {
                    rng.gen::<u8>()
                } else {
                    *b
                }
            })
            .collect()
    }

    proptest! {
    #![proptest_config(ProptestConfig::with_cases(10))]
    #[test]
        fn test_update(UserData(xs) in UserData::arbitrary()
        )
        {
            // start with some random user data
            let mut xs_blob = FieldBlob::<Vesta>::encode::<_, DefaultFqSponge<VestaParameters, PlonkSpongeConstantsKimchi>>(&*SRS, *DOMAIN, &xs);

            // randomly update this data and then update the blob
            let ys = random_perturbation(0.25, &xs);
            let d = make_diff(&*DOMAIN, &xs, &ys);
            xs_blob.update::<DefaultFqSponge<VestaParameters, PlonkSpongeConstantsKimchi>>(&*SRS, &*DOMAIN, d);

            // check that the user and SP agree on the new data
            let user_commitments = {
                let elems = encode_for_domain(&*DOMAIN, &ys);
                commit_to_field_elems(&*SRS, *DOMAIN, elems)
            };
            let ys_blob = FieldBlob::<Vesta>::encode::<_, DefaultFqSponge<VestaParameters, PlonkSpongeConstantsKimchi>>(&*SRS, *DOMAIN, &ys);
            prop_assert_eq!(user_commitments.clone(), ys_blob.commitments.clone());

            // the updated blob should be the same as if we just start with the new data
            prop_assert_eq!(xs_blob, ys_blob)
        }

    }
}
