use ark_ff::{PrimeField, Zero};
use ark_poly::{univariate::DensePolynomial, EvaluationDomain, Evaluations};
use rayon::prelude::*;
use std::ops::{Mul, Sub};
use thiserror::Error;
use tracing::instrument;

pub struct IndexQuery {
    chunks: Vec<Vec<usize>>,
}

pub struct ConstraintPolys<F: PrimeField> {
    pub q: DensePolynomial<F>,
    pub d: DensePolynomial<F>,
    pub a: DensePolynomial<F>,
    pub t: DensePolynomial<F>,
}

#[derive(Debug, Error, Clone, PartialEq)]
pub enum ReadProofError {
    #[error("Nonzero remainder in construction of T polynomial!")]
    NonzeroRemainder,
    #[error("Division by vanishing polynomial failed in construction of T_polynomial!")]
    DivisionByVanishingPolynomialFailed,
}

impl<F: PrimeField> ConstraintPolys<F> {
    #[instrument(skip_all, level = "debug")]
    pub fn create<D: EvaluationDomain<F>>(
        domain: D,
        query: IndexQuery,
        blob_chunks: Vec<DensePolynomial<F>>,
    ) -> Result<Vec<ConstraintPolys<F>>, ReadProofError> {
        query
            .chunks
            .into_par_iter()
            .zip(blob_chunks.into_par_iter())
            .map(|(indices, d)| {
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
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        blob::FieldBlob,
        env,
        query::{QueryBytes, QueryField},
    };

    use super::*;
    use crate::utils::test_utils::*;
    use ark_poly::Radix2EvaluationDomain;
    use mina_curves::pasta::{Fp, Vesta, VestaParameters};
    use mina_poseidon::{constants::PlonkSpongeConstantsKimchi, sponge::DefaultFqSponge};
    use once_cell::sync::Lazy;
    use poly_commitment::{ipa::SRS, SRS as _};
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
                let field_query: QueryField<Fp> = q.into_query_field(DOMAIN.size(), blob.n_chunks()).expect("QueryBytes should be valid");
                IndexQuery { chunks: field_query.as_indices() }
              }
            ).collect();
            index_queries.into_iter().for_each(|q| {
              let cps = ConstraintPolys::<Fp>::create(*DOMAIN, q, blob.chunks.clone());
              assert!(cps.is_ok());
            });

          }
        }
}
