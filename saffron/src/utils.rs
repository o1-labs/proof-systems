use std::marker::PhantomData;

use ark_ff::{BigInteger, PrimeField};
use ark_poly::EvaluationDomain;
use o1_utils::FieldHelpers;

// For injectivity, you can only use this on inputs of length at most
// 'F::MODULUS_BIT_SIZE / 8', e.g. for Vesta this is 31.
fn encode<Fp: PrimeField>(bytes: &[u8]) -> Fp {
    Fp::from_be_bytes_mod_order(bytes)
}

pub fn decode_into<Fp: PrimeField>(buffer: &mut [u8], x: Fp) {
    let bytes = x.into_bigint().to_bytes_be();
    buffer.copy_from_slice(&bytes);
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

#[derive(Copy, Clone, PartialEq, PartialOrd, Eq, Ord, Debug)]
/// We store the data in a vector of vector of field element
/// The inner vector represent polynomials
pub struct FieldElt {
    /// the number of the polynomial the data point is attached too
    poly_nb: usize,
    /// the number of the root of unity the data point is attached too
    eval_nb: usize,
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
    tag: PhantomData<F>
}

impl<F: PrimeField> QueryField<F> {
    pub fn is_valid(&self, nb_poly: usize) -> bool {
        self.start.eval_nb < 1 << 16
            && self.end.eval_nb < 1 << 16
            && self.end.poly_nb < nb_poly
            && self.start <= self.end
            && self.leftover_end <= (F::MODULUS_BIT_SIZE as usize) / 8
            && self.leftover_start <= (F::MODULUS_BIT_SIZE as usize) / 8
    }

    pub fn apply(self, data: Vec<Vec<F>>) -> Vec<u8> {
        assert!(self.is_valid(data.len()), "Invalid query");
        let mut answer: Vec<u8> = Vec::new();
        let mut field_elt = self.start;
        let n = (F::MODULUS_BIT_SIZE / 8) as usize;
        let m = F::size_in_bytes();
        let mut buffer = vec![0u8; m];
        while field_elt <= self.end {
            decode_into(&mut buffer, data[field_elt.poly_nb][field_elt.eval_nb]);
            answer.extend_from_slice(&buffer[(m - n)..m]);
            field_elt = field_elt.next().unwrap();
        }
        // trimming the first and last 31bytes chunk
        answer[(self.leftover_start)..(answer.len() - self.leftover_end)].to_vec()
    }
}

impl Iterator for FieldElt {
    type Item = FieldElt;
    fn next(&mut self) -> Option<FieldElt> {
        if self.eval_nb < (1 << 16) - 1 {
            self.eval_nb += 1;
        } else {
            self.poly_nb += 1;
            self.eval_nb = 0
        };
        Some(*self)
    }
}

impl<F: PrimeField> Into<QueryField<F>> for QueryBytes {
    fn into(self) -> QueryField<F> {
        let n = F::MODULUS_BIT_SIZE as usize / 8;
        let start_field_nb = self.start / n;
        let start = FieldElt {
            poly_nb: start_field_nb / (1 << 16),
            eval_nb: start_field_nb % (1 << 16),
        };
        let leftover_start = self.start % n;

        let byte_end = self.start + self.len;
        let end_field_nb = byte_end / n;
        let end = FieldElt {
            poly_nb: end_field_nb / (1 << 16),
            eval_nb: end_field_nb % (1 << 16),
        };
        let leftover_end = n - byte_end % n;
        QueryField {
            start,
            leftover_start,
            end,
            leftover_end,
            tag: PhantomData,
        }
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
    use ark_std::UniformRand;
    use mina_curves::pasta::Fp;
    use once_cell::sync::Lazy;
    use proptest::prelude::*;
    use test_utils::UserData;

    fn decode<Fp: PrimeField>(x: Fp) -> Vec<u8> {
        let mut buffer = vec![0u8; Fp::size_in_bytes()];
        decode_into(&mut buffer, x);
        buffer
    }

    fn decode_from_field_elements<F: PrimeField>(xs: Vec<F>) -> Vec<u8> {
        let n = (F::MODULUS_BIT_SIZE / 8) as usize;
        let m = F::size_in_bytes();
        let mut buffer = vec![0u8; F::size_in_bytes()];
        xs.iter()
            .flat_map(|x| {
                decode_into(&mut buffer, *x);
                buffer[(m - n)..m].to_vec()
            })
            .collect()
    }

    // Check that [u8] -> Fp -> [u8] is the identity function.
    proptest! {
        #[test]
        fn test_round_trip_from_bytes(xs in any::<[u8;31]>())
          { let n : Fp = encode(&xs);
            let ys : [u8; 31] = decode(n).as_slice()[1..32].try_into().unwrap();
            prop_assert_eq!(xs, ys);
          }
    }

    // Check that Fp -> [u8] -> Fp is the identity function.
    proptest! {
        #[test]
        fn test_round_trip_from_fp(
            x in prop::strategy::Just(Fp::rand(&mut ark_std::rand::thread_rng()))
        ) {
            let bytes = decode(x);
            let y = encode(&bytes);
            prop_assert_eq!(x,y);
        }
    }

    static DOMAIN: Lazy<Radix2EvaluationDomain<Fp>> = Lazy::new(|| {
        const SRS_SIZE: usize = 1 << 16;
        Radix2EvaluationDomain::new(SRS_SIZE).unwrap()
    });

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

    fn padded_field_length(xs: &[u8]) -> usize {
        let m = Fp::MODULUS_BIT_SIZE as usize / 8;
        let n = xs.len();
        let num_field_elems = (n + m - 1) / m;
        let num_polys = (num_field_elems + DOMAIN.size() - 1) / DOMAIN.size();
        DOMAIN.size() * num_polys
    }

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
            for query in queries {
                let expected = &xs[query.start..(query.start+query.len)];
                let field_query: QueryField<Fp> = query.clone().into();
                let got_answer = field_query.apply(chunked.clone());  // Note: might need clone depending on your types
                prop_assert_eq!(expected, got_answer);
            }
        }
    }
}
