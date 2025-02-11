use ark_ff::{BigInteger, PrimeField};
use ark_poly::EvaluationDomain;

// For injectivity, you can only use this on inputs of length at most
// 'F::MODULUS_BIT_SIZE / 8', e.g. for Vesta this is 31.
pub fn encode<Fp: PrimeField>(bytes: &[u8]) -> Fp {
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

// The number of field elements required to encode the data, including the padding
pub fn padded_field_length<F: PrimeField, D: EvaluationDomain<F>>(domain: &D, xs: &[u8]) -> usize {
    let n = min_encoding_chunks(domain, xs);
    n * domain.size()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_poly::Radix2EvaluationDomain;
    use ark_std::UniformRand;
    use mina_curves::pasta::Fp;
    use o1_utils::FieldHelpers;
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

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(20))]
        #[test]
        fn test_padded_byte_length(UserData(xs) in UserData::arbitrary()
    )
          { let chunked = encode_for_domain(&*DOMAIN, &xs);
            let n = chunked.into_iter().flatten().count();
            prop_assert_eq!(n, padded_field_length(&*DOMAIN, &xs));
          }
        }
}
