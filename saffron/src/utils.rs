use crate::encoding::decode_into;
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::PrimeField;
use ark_poly::EvaluationDomain;
use o1_utils::field_helpers::pows;
use std::marker::PhantomData;
use thiserror::Error;
use tracing::instrument;

#[derive(Clone, Debug)]
/// Represents the bytes a user query
pub struct QueryBytes {
    pub start: usize,
    pub len: usize,
}

#[derive(Copy, Clone, PartialEq, PartialOrd, Eq, Ord, Debug)]
/// We store the data in a vector of vector of field element
/// The inner vector represent polynomials
struct FieldElt {
    /// the index of the polynomial the data point is attached too
    poly_index: usize,
    /// the index of the root of unity the data point is attached too
    eval_index: usize,
    domain_size: usize,
    n_polys: usize,
}
/// Represents a query in term of Field element
#[derive(Debug)]
pub struct QueryField<F> {
    start: FieldElt,
    /// how many bytes we need to trim from the first chunk
    /// we get from the first field element we decode
    leftover_start: usize,
    end: FieldElt,
    /// how many bytes we need to trim from the last chunk
    /// we get from the last field element we decode
    leftover_end: usize,
    tag: PhantomData<F>,
}

impl<F: PrimeField> QueryField<F> {
    #[instrument(skip_all, level = "debug")]
    pub fn apply(self, data: &[Vec<F>]) -> Vec<u8> {
        let n = (F::MODULUS_BIT_SIZE / 8) as usize;
        let mut buffer = vec![0u8; n];
        let mut answer = Vec::new();
        self.start
            .into_iter()
            .take_while(|x| x <= &self.end)
            .for_each(|x| {
                let value = data[x.poly_index][x.eval_index];
                decode_into(&mut buffer, value);
                answer.extend_from_slice(&buffer);
            });

        answer[(self.leftover_start)..(answer.len() - self.leftover_end)].to_vec()
    }
}

impl Iterator for FieldElt {
    type Item = FieldElt;
    fn next(&mut self) -> Option<Self::Item> {
        let current = *self;

        if (self.eval_index + 1) < self.domain_size {
            self.eval_index += 1;
        } else if (self.poly_index + 1) < self.n_polys {
            self.poly_index += 1;
            self.eval_index = 0;
        } else {
            return None;
        }

        Some(current)
    }
}

#[derive(Debug, Error, Clone, PartialEq)]
pub enum QueryError {
    #[error("Query out of bounds: poly_index {poly_index} eval_index {eval_index} n_polys {n_polys} domain_size {domain_size}")]
    QueryOutOfBounds {
        poly_index: usize,
        eval_index: usize,
        n_polys: usize,
        domain_size: usize,
    },
}

impl QueryBytes {
    pub fn into_query_field<F: PrimeField>(
        &self,
        domain_size: usize,
        n_polys: usize,
    ) -> Result<QueryField<F>, QueryError> {
        let n = (F::MODULUS_BIT_SIZE / 8) as usize;
        let start = {
            let start_field_nb = self.start / n;
            FieldElt {
                poly_index: start_field_nb / domain_size,
                eval_index: start_field_nb % domain_size,
                domain_size,
                n_polys,
            }
        };
        let byte_end = self.start + self.len;
        let end = {
            let end_field_nb = byte_end / n;
            FieldElt {
                poly_index: end_field_nb / domain_size,
                eval_index: end_field_nb % domain_size,
                domain_size,
                n_polys,
            }
        };

        if start.poly_index >= n_polys || end.poly_index >= n_polys {
            return Err(QueryError::QueryOutOfBounds {
                poly_index: end.poly_index,
                eval_index: end.eval_index,
                n_polys,
                domain_size,
            });
        };

        let leftover_start = self.start % n;
        let leftover_end = n - byte_end % n;

        Ok(QueryField {
            start,
            leftover_start,
            end,
            leftover_end,
            tag: std::marker::PhantomData,
        })
    }
}

#[cfg(test)]
pub mod test_utils {
    use proptest::prelude::*;

    #[derive(Debug, Clone)]
    pub struct UserData(pub Vec<u8>);

    impl UserData {
        pub fn len(&self) -> usize {
            self.0.len()
        }

        pub fn is_empty(&self) -> bool {
            self.0.is_empty()
        }
    }

    #[derive(Clone, Debug)]
    pub enum DataSize {
        Small,
        Medium,
        Large,
    }

    impl DataSize {
        const KB: usize = 1_000;
        const MB: usize = 1_000_000;

        fn size_range_bytes(&self) -> (usize, usize) {
            match self {
                // Small: 1KB - 1MB
                Self::Small => (Self::KB, Self::MB),
                // Medium: 1MB - 10MB
                Self::Medium => (Self::MB, 10 * Self::MB),
                // Large: 10MB - 100MB
                Self::Large => (10 * Self::MB, 100 * Self::MB),
            }
        }
    }

    impl Arbitrary for DataSize {
        type Parameters = ();
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(_: ()) -> Self::Strategy {
            prop_oneof![
                6 => Just(DataSize::Small), // 60% chance
                3 => Just(DataSize::Medium),
                1 => Just(DataSize::Large)
            ]
            .boxed()
        }
    }

    impl Default for DataSize {
        fn default() -> Self {
            Self::Small
        }
    }

    impl Arbitrary for UserData {
        type Parameters = DataSize;
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary() -> Self::Strategy {
            DataSize::arbitrary()
                .prop_flat_map(|size| {
                    let (min, max) = size.size_range_bytes();
                    prop::collection::vec(any::<u8>(), min..max)
                })
                .prop_map(UserData)
                .boxed()
        }

        fn arbitrary_with(size: Self::Parameters) -> Self::Strategy {
            let (min, max) = size.size_range_bytes();
            prop::collection::vec(any::<u8>(), min..max)
                .prop_map(UserData)
                .boxed()
        }
    }
}

// returns the minimum number of polynomials required to encode the data
pub fn min_encoding_chunks<F: PrimeField, D: EvaluationDomain<F>>(domain: &D, xs: &[u8]) -> usize {
    let m = F::MODULUS_BIT_SIZE as usize / 8;
    let n = xs.len();
    let num_field_elems = (n + m - 1) / m;
    (num_field_elems + domain.size() - 1) / domain.size()
}

pub fn chunk_size_in_bytes<F: PrimeField, D: EvaluationDomain<F>>(domain: &D) -> usize {
    let m = F::MODULUS_BIT_SIZE as usize / 8;
    domain.size() * m
}

/// For commitments C_i and randomness r, returns ∑ r^i C_i.
pub fn aggregate_commitments<G: AffineRepr>(randomness: G::ScalarField, commitments: &[G]) -> G {
    // powers_of_randomness = [1, r, r², r³, …]
    let powers_of_randomness = pows(commitments.len(), randomness);
    let aggregated_commitment =
    // Using unwrap() is safe here, as err is returned when commitments and powers have different lengths,
    // and powers are built with commitment.len().
        G::Group::msm(commitments, powers_of_randomness.as_slice()).unwrap().into_affine();
    aggregated_commitment
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::encode_for_domain;
    use ark_poly::Radix2EvaluationDomain;
    use mina_curves::pasta::Fp;
    use once_cell::sync::Lazy;
    use proptest::prelude::*;
    use test_utils::{DataSize, UserData};
    use tracing::debug;

    static DOMAIN: Lazy<Radix2EvaluationDomain<Fp>> = Lazy::new(|| {
        const SRS_SIZE: usize = 1 << 16;
        Radix2EvaluationDomain::new(SRS_SIZE).unwrap()
    });

    // The number of field elements required to encode the data, including the padding
    fn padded_field_length(xs: &[u8]) -> usize {
        let n = min_encoding_chunks(&*DOMAIN, xs);
        n * DOMAIN.size()
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(20))]
        #[test]
        fn test_padded_byte_length(UserData(xs) in UserData::arbitrary()
    )
          { let chunked = encode_for_domain::<Fp>(DOMAIN.size(), &xs);
            let n = chunked.into_iter().flatten().count();
            prop_assert_eq!(n, padded_field_length(&xs));
          }
        }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(20))]
        #[test]
        fn test_query(
            (UserData(xs), queries) in UserData::arbitrary()
                .prop_flat_map(|xs| {
                    let n = xs.len();
                    let query_strategy = (0..(n - 1)).prop_flat_map(move |start| {
                        ((start + 1)..n).prop_map(move |end| QueryBytes { start, len: end - start})
                    });
                    let queries_strategy = prop::collection::vec(query_strategy, 10);
                    (Just(xs), queries_strategy)
                })
        ) {
            let chunked = encode_for_domain(DOMAIN.size(), &xs);
            for query in queries {
                let expected = &xs[query.start..(query.start+query.len)];
                let field_query: QueryField<Fp> = query.into_query_field(DOMAIN.size(), chunked.len()).unwrap();
                let got_answer = field_query.apply(&chunked);
                prop_assert_eq!(expected, got_answer);
            }
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(20))]
        #[test]
        fn test_for_invalid_query_length(
            (UserData(xs), mut query) in UserData::arbitrary()
                .prop_flat_map(|UserData(xs)| {
                    let padded_len = {
                        let m = Fp::MODULUS_BIT_SIZE as usize / 8;
                        padded_field_length(&xs) * m
                    };
                    let query_strategy = (0..xs.len()).prop_map(move |start| {
                        // this is the last valid end point
                        let end = padded_len - 1;
                        QueryBytes { start, len: end - start }
                    });
                    (Just(UserData(xs)), query_strategy)
                })
        ) {
            debug!("check that first query is valid");
            let chunked = encode_for_domain::<Fp>(DOMAIN.size(), &xs);
            let n_polys = chunked.len();
            let query_field = query.into_query_field::<Fp>(DOMAIN.size(), n_polys);
            prop_assert!(query_field.is_ok());
            debug!("check that extending query length by 1 is invalid");
            query.len += 1;
            let query_field = query.into_query_field::<Fp>(DOMAIN.size(), n_polys);
            prop_assert!(query_field.is_err());

        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(20))]
        #[test]
        fn test_nil_query(
            (UserData(xs), query) in UserData::arbitrary_with(DataSize::Small)
                .prop_flat_map(|xs| {
                    let padded_len = {
                        let m = Fp::MODULUS_BIT_SIZE as usize / 8;
                        padded_field_length(&xs.0) * m
                    };
                    let query_strategy = (0..padded_len).prop_map(move |start| {
                        QueryBytes { start, len: 0 }
                    });
                    (Just(xs), query_strategy)
                })
        ) {
            let chunked = encode_for_domain(DOMAIN.size(), &xs);
            let n_polys = chunked.len();
            let field_query: QueryField<Fp> = query.into_query_field(DOMAIN.size(), n_polys).unwrap();
            let got_answer = field_query.apply(&chunked);
            prop_assert!(got_answer.is_empty());
            }

    }
}
