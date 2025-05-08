//! This file handles bytes <-> scalar conversions for Saffron.
//! Unless specified in the function's name, conversions are made over
//! `F::MODULUS_BIT_SIZE / 8` bytes (31 bytes for Pallas & Vesta). Functions
//! that convert over `F::size_in_bytes()` are suffixed with `_full` (this size
//! is 32 bytes for Pallas & Vesta fields elements)

use ark_ff::{BigInteger, PrimeField};

// For injectivity, you can only use this on inputs of length at most
// 'F::MODULUS_BIT_SIZE / 8', e.g. for Pallas & Vesta this is 31.
/// Converts `bytes` into a field element ; `bytes` length can be arbitrary.
pub fn encode<F: PrimeField>(bytes: &[u8]) -> F {
    F::from_be_bytes_mod_order(bytes)
}

/// Returns the `Fp::size_in_bytes()` decimal representation of `x`
/// in big endian (for Pallas & Vesta, the representation is 32 bytes)
pub fn decode_into_vec_full<F: PrimeField>(x: F) -> Vec<u8> {
    x.into_bigint().to_bytes_be()
}

/// Copies in `buffer` the `Fp::size_in_bytes()` decimal representation of `x`
/// in big endian (for Pallas & Vesta, the representation is 32 bytes)
pub fn decode_into_full<F: PrimeField>(buffer: &mut [u8], x: F) {
    let bytes = decode_into_vec_full(x);
    buffer.copy_from_slice(&bytes);
}

/// Converts each chunk of size `F::MODULUS_BIT_SIZE / 8` from `bytes` to a field element
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

/// Same as [encode_as_field_elements], but the returned vector is divided in
/// chunks of `domain_size` (except for the last chunk if its size is smaller)
pub fn encode_for_domain<F: PrimeField>(domain_size: usize, bytes: &[u8]) -> Vec<Vec<F>> {
    let xs = encode_as_field_elements(bytes);
    xs.chunks(domain_size)
        .map(|chunk| {
            if chunk.len() < domain_size {
                let mut padded_chunk = Vec::with_capacity(domain_size);
                padded_chunk.extend_from_slice(chunk);
                padded_chunk.resize(domain_size, F::zero());
                padded_chunk
            } else {
                chunk.to_vec()
            }
        })
        .collect()
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::decode_into_full;
    use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
    use ark_std::UniformRand;
    use mina_curves::pasta::Fp;
    use o1_utils::FieldHelpers;
    use once_cell::sync::Lazy;
    use proptest::prelude::*;

    use crate::utils::test_utils::UserData;

    fn decode_from_field_elements<F: PrimeField>(xs: Vec<F>) -> Vec<u8> {
        let n = (F::MODULUS_BIT_SIZE / 8) as usize;
        let m = F::size_in_bytes();
        let mut buffer = vec![0u8; F::size_in_bytes()];
        xs.iter()
            .flat_map(|x| {
                decode_into_full(&mut buffer, *x);
                buffer[(m - n)..m].to_vec()
            })
            .collect()
    }

    // Check that [u8] -> Fp -> [u8] is the identity function.
    proptest! {
        #[test]
        fn test_round_trip_from_bytes(xs in any::<[u8;31]>())
          { let n : Fp = encode(&xs);
            let ys : [u8; 31] = decode_into_vec_full(n).as_slice()[1..32].try_into().unwrap();
            prop_assert_eq!(xs, ys);
          }
    }

    // Check that Fp -> [u8] -> Fp is the identity function.
    proptest! {
        #[test]
        fn test_round_trip_from_fp(
            x in prop::strategy::Just(Fp::rand(&mut ark_std::rand::thread_rng()))
        ) {
            let bytes = decode_into_vec_full(x);
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
          { let chunked = encode_for_domain::<Fp>(DOMAIN.size(), &xs);
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
}
