use crate::{blob::FieldBlob, query::QueryField};
use ark_ff::{One, PrimeField, Zero};
use ark_poly::{
    univariate::DensePolynomial, EvaluationDomain, Evaluations, Polynomial, Radix2EvaluationDomain,
};
use kimchi::curve::KimchiCurve;
use mina_poseidon::FqSponge;
use poly_commitment::{
    commitment::{
        absorb_commitment, combined_inner_product, BatchEvaluationProof, CommitmentCurve,
        Evaluation,
    },
    ipa::{OpeningProof, SRS},
    utils::DensePolynomialOrEvaluations,
    PolyComm, SRS as _,
};
use rand::rngs::OsRng;
use std::ops::{Mul, Sub};
use thiserror::Error;
use tracing::instrument;

#[derive(Clone, Debug)]
pub struct ReadProof<G: CommitmentCurve> {
    pub commitment: Commitment<G>,
    pub evals: Evals<G::ScalarField>,
    pub proof: OpeningProof<G>,
}

#[instrument(skip_all, level = "debug")]
pub fn read_proof<
    G: KimchiCurve,
    D: EvaluationDomain<G::ScalarField>,
    EFqSponge: Clone + FqSponge<G::BaseField, G, G::ScalarField>,
>(
    srs: &SRS<G>,
    domain: D,
    group_map: &G::Map,
    blob: FieldBlob<G>,
    query: &QueryField<G::ScalarField>,
    rng: &mut OsRng,
) -> Result<Vec<ReadProof<G>>, ReadProofError>
where
    G::BaseField: PrimeField,
{
    blob.chunks
        .into_iter()
        .zip(query.as_indices().chunks.into_iter())
        .map(|(chunk, indices)| {
            let poly = ConstraintPolys::create(domain, indices, chunk)?;
            let commitment = poly.commit(srs);
            let mut sponge = EFqSponge::new(G::other_curve_sponge_params());
            let z = commitment.derive_challenge_point(&mut sponge);
            let evals = poly.evaluate(z);
            sponge.absorb_fr(&[evals.t, evals.q, evals.d, evals.a]);
            let proof = srs.open(
                group_map,
                &[
                    (
                        DensePolynomialOrEvaluations::<
                            G::ScalarField,
                            Radix2EvaluationDomain<G::ScalarField>,
                        >::DensePolynomial(&poly.t),
                        PolyComm::new(vec![G::ScalarField::zero()]),
                    ),
                    (
                        DensePolynomialOrEvaluations::DensePolynomial(&poly.q),
                        PolyComm::new(vec![G::ScalarField::zero()]),
                    ),
                    (
                        DensePolynomialOrEvaluations::DensePolynomial(&poly.d),
                        PolyComm::new(vec![G::ScalarField::zero()]),
                    ),
                    (
                        DensePolynomialOrEvaluations::DensePolynomial(&poly.a),
                        PolyComm::new(vec![G::ScalarField::zero()]),
                    ),
                ],
                &[z],
                G::ScalarField::one(), // Single evaluation, so we don't care
                G::ScalarField::one(), // Single evaluation, so we don't care
                sponge,
                rng,
            );
            Ok(ReadProof {
                commitment,
                evals,
                proof,
            })
        })
        .collect()
}

#[instrument(skip_all, level = "debug")]
pub fn verify_read_proof<
    G: KimchiCurve,
    EFqSponge: Clone + FqSponge<G::BaseField, G, G::ScalarField>,
>(
    srs: &SRS<G>,
    domain: &Radix2EvaluationDomain<G::ScalarField>,
    group_map: &G::Map,
    proof: ReadProof<G>,
    rng: &mut OsRng,
) -> bool
where
    G::BaseField: PrimeField,
{
    let mut sponge = EFqSponge::new(G::other_curve_sponge_params());
    let z = proof.commitment.derive_challenge_point(&mut sponge);
    sponge.absorb_fr(&[proof.evals.t, proof.evals.q, proof.evals.d, proof.evals.a]);

    let evaluations = vec![
        Evaluation {
            commitment: proof.commitment.t,
            evaluations: vec![vec![proof.evals.t]],
        },
        Evaluation {
            commitment: proof.commitment.q,
            evaluations: vec![vec![proof.evals.q]],
        },
        Evaluation {
            commitment: proof.commitment.d,
            evaluations: vec![vec![proof.evals.d]],
        },
        Evaluation {
            commitment: proof.commitment.a,
            evaluations: vec![vec![proof.evals.a]],
        },
    ];

    let v = G::ScalarField::one();
    let u = G::ScalarField::one();

    let combined_inner_product = {
        let es: Vec<_> = evaluations
            .iter()
            .map(|Evaluation { evaluations, .. }| evaluations.clone())
            .collect();

        combined_inner_product(&v, &u, es.as_slice())
    };
    let opening_proof_verifies = srs.verify(
        group_map,
        &mut [BatchEvaluationProof {
            sponge: sponge.clone(),
            evaluation_points: vec![z],
            polyscale: v,
            evalscale: u,
            evaluations,
            opening: &proof.proof,
            combined_inner_product,
        }],
        rng,
    );
    let evaluations_verify = {
        let z_n = domain.vanishing_polynomial();
        proof.evals.t == (proof.evals.a - proof.evals.q * proof.evals.d) / z_n.evaluate(&z)
    };
    opening_proof_verifies && evaluations_verify
}

#[derive(Clone, Debug)]
pub struct ReadProofPolys<T> {
    pub q: T,
    pub d: T,
    pub a: T,
    pub t: T,
}

#[derive(Debug, Error, Clone, PartialEq)]
pub enum ReadProofError {
    #[error("Nonzero remainder in construction of T polynomial!")]
    NonzeroRemainder,
    #[error("Division by vanishing polynomial failed in construction of T_polynomial!")]
    DivisionByVanishingPolynomialFailed,
}

type ConstraintPolys<F> = ReadProofPolys<DensePolynomial<F>>;

type Commitment<G> = ReadProofPolys<PolyComm<G>>;

type Evals<F> = ReadProofPolys<F>;

impl<F: PrimeField> ConstraintPolys<F> {
    #[instrument(skip_all, level = "debug")]
    pub fn create<D: EvaluationDomain<F>>(
        domain: D,
        indices: Vec<usize>,
        d: DensePolynomial<F>,
    ) -> Result<ConstraintPolys<F>, ReadProofError> {
        let mut evals = d.evaluate_over_domain_by_ref(domain);
        let q_evals = {
            let mut v = vec![F::zero(); domain.size()];
            indices.iter().for_each(|i| {
                v[*i] = F::one();
            });
            Evaluations::from_vec_and_domain(v, domain)
        };
        evals *= &q_evals;
        let q = q_evals.interpolate();
        let a = evals.interpolate();
        let t_opt = {
            let prod = q.mul(&d);
            let numerator = a.sub(&prod);
            numerator.divide_by_vanishing_poly(domain)
        };
        let t = match t_opt {
            Some((quot, rem)) => {
                if !rem.is_zero() {
                    return Err(ReadProofError::NonzeroRemainder);
                } else {
                    Ok(quot)
                }
            }
            None => Err(ReadProofError::DivisionByVanishingPolynomialFailed),
        }?;
        Ok(ConstraintPolys { q, d, a, t })
    }

    pub fn commit<G: CommitmentCurve<ScalarField = F>>(&self, srs: &SRS<G>) -> Commitment<G> {
        let num_chunks = 1;
        Commitment {
            q: srs.commit_non_hiding(&self.q, num_chunks),
            d: srs.commit_non_hiding(&self.d, num_chunks),
            a: srs.commit_non_hiding(&self.a, num_chunks),
            t: srs.commit_non_hiding(&self.t, num_chunks),
        }
    }

    pub fn evaluate(&self, point: F) -> Evals<F> {
        Evals {
            q: self.q.evaluate(&point),
            d: self.d.evaluate(&point),
            a: self.a.evaluate(&point),
            t: self.t.evaluate(&point),
        }
    }
}

impl<G: CommitmentCurve> Commitment<G> {
    pub fn derive_challenge_point<EFqSponge>(&self, sponge: &mut EFqSponge) -> G::ScalarField
    where
        EFqSponge: FqSponge<G::BaseField, G, G::ScalarField>,
    {
        absorb_commitment(sponge, &self.t);
        absorb_commitment(sponge, &self.q);
        absorb_commitment(sponge, &self.d);
        absorb_commitment(sponge, &self.a);
        sponge.challenge()
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        blob::FieldBlob,
        env,
        query::{IndexQuery, QueryBytes, QueryField},
    };

    use super::*;
    use crate::utils::test_utils::*;
    use ark_poly::Radix2EvaluationDomain;
    use kimchi::groupmap::GroupMap;
    use mina_curves::pasta::{Fp, Vesta, VestaParameters};
    use mina_poseidon::{constants::PlonkSpongeConstantsKimchi, sponge::DefaultFqSponge};
    use once_cell::sync::Lazy;
    use poly_commitment::ipa::SRS;
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

    static GROUP_MAP: Lazy<<Vesta as CommitmentCurve>::Map> =
        Lazy::new(<Vesta as CommitmentCurve>::Map::setup);

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(10))]
        #[test]
        fn test_constraint_poly_creation((UserData(xs), queries) in UserData::arbitrary()
               .prop_flat_map(|xs| {
                   let n = xs.len();
                   let query_strategy = (0..(n - 1)).prop_flat_map(move |start| {
                       ((start + 1)..n).prop_map(move |end| QueryBytes { start, len: end - start})
                   });
                   let queries_strategy = prop::collection::vec(query_strategy, 5);
                   (Just(xs), queries_strategy)
               })

    )
          { let blob = FieldBlob::<Vesta>::encode::<_, VestaFqSponge>(&*SRS, *DOMAIN, &xs);
            let index_queries: Vec<IndexQuery> =
              queries.into_iter().map(|q| {
                let query_field: QueryField<Fp> = q.into_query_field(DOMAIN.size(), blob.n_chunks()).expect("QueryBytes should be valid");
                query_field.as_indices()
              }
            ).collect();
            index_queries.into_iter().for_each(|q| {
              blob.chunks.iter().zip(q.chunks.into_iter()).for_each(|(chunk, indices)| {
                let cps = ConstraintPolys::<Fp>::create(*DOMAIN, indices, chunk.clone());
                assert!(cps.is_ok());

            });
          });
        }
    }

    proptest! {
            #![proptest_config(ProptestConfig::with_cases(2))]
            #[test]
            fn test_read_proof((UserData(xs), queries) in UserData::arbitrary()
                   .prop_flat_map(|xs| {
                       let n = xs.len();
                       let query_strategy = (0..(n - 1)).prop_flat_map(move |start| {
                           ((start + 1)..n).prop_map(move |end| QueryBytes { start, len: end - start})
                       });
                       let queries_strategy = prop::collection::vec(query_strategy, 5);
                       (Just(xs), queries_strategy)
                   })

        )
          { let mut rng = OsRng;
            let blob = FieldBlob::<Vesta>::encode::<_, VestaFqSponge>(&*SRS, *DOMAIN, &xs);
            queries.into_iter().for_each(|q| {
                let query_field = q.into_query_field(DOMAIN.size(), blob.n_chunks()).expect("QueryBytes should be valid");
                let query_res = blob.query(*DOMAIN, &query_field);
                let proofs = read_proof::<Vesta, _, VestaFqSponge>(&*SRS, *DOMAIN, &*GROUP_MAP, blob.clone(), &query_field, &mut rng).expect("Read proof should be valid");

                // Check that the commitments match what the user would expect based on the query results
                {
                  let query_evals = query_res.as_evaluations(*DOMAIN);
                  proofs.clone().into_iter().zip(query_evals.into_iter()).for_each(|(proof, evals)| {
                      let user_commitment = SRS.commit_evaluations_non_hiding(*DOMAIN, &evals);
                      assert_eq!(user_commitment, proof.commitment.a);
                  });

                }

                // Check that the proof verifies
                proofs.into_iter().for_each(|proof| {
                  let res = verify_read_proof::<Vesta, VestaFqSponge>(&*SRS, &*DOMAIN, &*GROUP_MAP, proof, &mut rng);
                  assert!(res);
                });

                // Check that the query results match the data
                // Since we assume that the query was a slice, we can throw away the indices now
                let query_res_bytes: Vec<u8> = {
                    let decode = query_field.result_decoder();
                    decode(&query_res)
                };
                assert_eq!(query_res_bytes, xs[q.start.. q.start + q.len]);


          });
        }
    }
}
