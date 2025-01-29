use ark_ff::{BigInteger, PrimeField};
use ark_poly::EvaluationDomain;
use o1_utils::FieldHelpers;
use thiserror::Error;
use tracing::instrument;

// For injectivity, you can only use this on inputs of length at most
// 'F::MODULUS_BIT_SIZE / 8', e.g. for Vesta this is 31.
fn encode<Fp: PrimeField>(bytes: &[u8]) -> Fp {
    Fp::from_be_bytes_mod_order(bytes)
}

pub fn decode_into<Fp: PrimeField>(buffer: &mut [u8], x: &Fp) {
    let bytes = x.into_bigint().to_bytes_be();
    buffer.copy_from_slice(&bytes);
}

fn decode<F: PrimeField>(x: &F) -> Vec<u8> {
    let n = (F::MODULUS_BIT_SIZE / 8) as usize;
    let m = F::size_in_bytes();
    let mut buffer = vec![0u8; m];
    decode_into(&mut buffer, x);
    buffer[(m - n)..m].to_vec()
}

pub fn encode_as_field_elements<F: PrimeField>(bytes: &[u8]) -> Vec<F> {
    let n = (F::MODULUS_BIT_SIZE / 8) as usize;
    bytes
        .chunks(n)
        .map(|chunk| {
            let mut bytes = vec![0u8; n];
            bytes[..chunk.len()].copy_from_slice(chunk);
            encode(&bytes)
        })
        .collect::<Vec<_>>()
}

pub fn encode_for_domain<F: PrimeField, D: EvaluationDomain<F>>(
    domain: &D,
    bytes: &[u8],
) -> Vec<Vec<F>> {
    let domain_size = domain.size();
    let xs = encode_as_field_elements(bytes);
    xs.chunks(domain_size)
        .map(|chunk| {
            if chunk.len() < domain.size() {
                let mut padded_chunk = Vec::with_capacity(domain.size());
                padded_chunk.extend_from_slice(chunk);
                padded_chunk.resize(domain.size(), F::zero());
                padded_chunk
            } else {
                chunk.to_vec()
            }
        })
        .collect()
}

#[derive(Clone, Debug)]
/// Represents the bytes a user query
pub struct QueryBytes {
    pub start: usize,
    pub len: usize,
}

#[derive(Clone, Copy, PartialEq, PartialOrd, Eq, Ord, Debug)]
/// We store the data in a vector of vector of field element
/// The inner vector represent polynomials
pub struct FieldElt {
    /// the number of the polynomial the data point is attached too
    poly_index: usize,
    /// the number of the root of unity the data point is attached too
    eval_index: usize,
    domain_size: usize,
    n_polys: usize,
}
/// Represents a query in term of Field element
#[derive(Debug)]
pub struct QueryField<F> {
    start: FieldElt,
    /// how many bytes we need to trim from the first 31bytes chunk
    /// we get from the first field element we decode
    leftover_start: usize,
    end: FieldElt,
    /// how many bytes we need to trim from the last 31bytes chunk
    /// we get from the last field element we decode
    leftover_end: usize,
    tag: std::marker::PhantomData<F>,
}

impl<F: PrimeField> QueryField<F> {
    #[instrument(skip_all, level = "debug")]
    pub fn apply(self, data: &[Vec<F>]) -> Result<Vec<u8>, QueryError> {
        let answer: Vec<u8> = self
            .start
            .into_iter()
            .take_while(|x| x <= &self.end)
            .flat_map(|x| {
                let value = data[x.poly_index][x.eval_index];
                decode(&value)
            })
            .collect();

        let n = answer.len();
        Ok(answer[(self.leftover_start)..(n - self.leftover_end)].to_vec())
    }
}

impl Iterator for FieldElt {
    type Item = FieldElt;
    fn next(&mut self) -> Option<Self::Item> {
        if self.eval_index == self.domain_size - 1 && self.poly_index == self.n_polys - 1 {
            return None;
        }

        let current = *self;

        if (self.eval_index + 1) < self.domain_size {
            self.eval_index += 1;
        } else {
            self.poly_index += 1;
            self.eval_index = 0;
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
        if start.poly_index >= n_polys {
            return Err(QueryError::QueryOutOfBounds {
                poly_index: start.poly_index,
                eval_index: start.eval_index,
                n_polys,
                domain_size,
            });
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
        if end.poly_index >= n_polys {
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

#[cfg(test)]
mod tests {
    use super::*;
    use ark_poly::Radix2EvaluationDomain;
    use mina_curves::pasta::Fp;
    use once_cell::sync::Lazy;
    use proptest::prelude::*;
    use test_utils::{DataSize, UserData};
    use tracing::debug;

    fn decode_from_field_elements<F: PrimeField>(xs: Vec<F>) -> Vec<u8> {
        xs.iter().flat_map(decode).collect()
    }

    fn padded_field_length(xs: &[u8]) -> usize {
        let m = Fp::MODULUS_BIT_SIZE as usize / 8;
        let n = xs.len();
        let num_field_elems = (n + m - 1) / m;
        let num_polys = (num_field_elems + DOMAIN.size() - 1) / DOMAIN.size();
        DOMAIN.size() * num_polys
    }

    // Check that [u8] -> Fp -> [u8] is the identity function for any length 31 bytestring.
    proptest! {
        #[test]
        fn test_round_trip_from_bytes(xs in any::<[u8;31]>())
          { let n : Fp = encode(&xs);
            let ys : [u8; 31] = decode(&n).try_into().unwrap();
            prop_assert_eq!(xs, ys);
          }
    }

    // Check that Fp -> [u8] -> Fp is the identity function when restricted to the range of encode
    proptest! {
        #[test]
        fn test_round_trip_from_fp(x in any::<[u8;31]>().prop_map(|xs| encode::<Fp>(&xs))) {

            let bytes = decode(&x);
            let y = encode(&bytes);
            prop_assert_eq!(x,y);
        }
    }

    static DOMAIN: Lazy<Radix2EvaluationDomain<Fp>> = Lazy::new(|| {
        const SRS_SIZE: usize = 1 << 16;
        Radix2EvaluationDomain::new(SRS_SIZE).unwrap()
    });

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(20))]
        #[test]
        fn test_padded_byte_length(UserData(xs) in UserData::arbitrary()
    )
          { let chunked = encode_for_domain(&*DOMAIN, &xs);
            let n = chunked.into_iter().flatten().count();
            prop_assert_eq!(n, padded_field_length(&xs));
          }
        }

    // check that Vec<u8> -> Vec<Vec<F>> -> Vec<u8> is the identity function
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(20))]
        #[test]
        fn test_round_trip_encoding_to_field_elems(UserData(xs) in UserData::arbitrary()
    )
          { let chunked = encode_for_domain(&*DOMAIN, &xs);
            let elems = chunked
              .into_iter()
              .flatten()
              .collect();
            let ys = decode_from_field_elements(elems)
              .into_iter()
              .take(xs.len())
              .collect::<Vec<u8>>();
            prop_assert_eq!(xs,ys);
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
            let chunked = encode_for_domain(&*DOMAIN, &xs);
            let n_polys = chunked.len();
            for query in queries {
                let expected = &xs[query.start..(query.start+query.len)];
                let field_query: QueryField<Fp> = query.into_query_field(DOMAIN.size(), n_polys).unwrap();
                let got_answer = field_query.apply(&chunked).unwrap();
                prop_assert_eq!(expected, got_answer);
            }
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
            let chunked = encode_for_domain(&*DOMAIN, &xs);
            let n_polys = chunked.len();
            let field_query: QueryField<Fp> = query.into_query_field(DOMAIN.size(), n_polys).unwrap();
            let got_answer = field_query.apply(&chunked).unwrap();
            prop_assert!(got_answer.is_empty());
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
            let chunked = encode_for_domain(&*DOMAIN, &xs);
            let n_polys = chunked.len();
            let query_field = query.into_query_field(DOMAIN.size(), n_polys).unwrap();
            let res = query_field.apply(&chunked);
            prop_assert!(res.is_ok());
            debug!("check that extending query length by 1 is invalid");
            query.len += 1;
            let query_field = query.into_query_field::<Fp>(DOMAIN.size(), n_polys);
            prop_assert!(query_field.is_err());

        }
    }
}
