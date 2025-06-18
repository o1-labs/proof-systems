//! This file handles bytes <-> scalar conversions for Saffron.
//! Unless specified in the function's name, conversions are made over
//! `F::MODULUS_BIT_SIZE / 8` bytes (31 bytes for Pallas & Vesta). Functions
//! that convert over `F::size_in_bytes()` are suffixed with `_full` (this size
//! is 32 bytes for Pallas & Vesta fields elements)

use ark_ff::{BigInteger, PrimeField};
use o1_utils::FieldHelpers;
use std::iter::repeat;

/// The size in bytes of the full representation of a field element (32 for
/// Pallas & Vesta)
pub(crate) fn encoding_size_full<F: PrimeField>() -> usize {
    F::size_in_bytes()
}

/// The number of bytes that can be fully represented by a scalar (31 for
/// Pallas & Vesta)
pub(crate) const fn encoding_size<F: PrimeField>() -> usize {
    (F::MODULUS_BIT_SIZE / 8) as usize
}

// For injectivity, you can only use this on inputs of length at most
// 'F::MODULUS_BIT_SIZE / 8', e.g. for Pallas & Vesta this is 31.
/// Converts `bytes` into a field element ; `bytes` length can be arbitrary.
pub fn encode<F: PrimeField>(bytes: &[u8]) -> F {
    F::from_be_bytes_mod_order(bytes)
}

/// Returns the `Fp::size_in_bytes()` decimal representation of `x`
/// in big endian (for Pallas & Vesta, the representation is 32 bytes)
pub(crate) fn decode_full<F: PrimeField>(x: F) -> Vec<u8> {
    x.into_bigint().to_bytes_be()
}

/// Converts provided field element `x` into a vector of bytes of size
/// `F::MODULUS_BIT_SIZE / 8`
fn decode<F: PrimeField>(x: F) -> Vec<u8> {
    // How many bytes fit into the field
    let n = encoding_size::<F>();
    // How many bytes are necessary to fit a field element
    let m = encoding_size_full::<F>();
    let full_bytes = decode_full(x);
    full_bytes[(m - n)..m].to_vec()
}

/// Converts provided field element `x` into a vector of bytes of size
/// `F::MODULUS_BIT_SIZE / 8`
pub(crate) fn decode_into<F: PrimeField>(buffer: &mut [u8], x: F) {
    let bytes = decode(x);
    buffer.copy_from_slice(&bytes);
}

/// Creates a bytes vector that represents each element of `xs` over 31 bytes
pub fn decode_from_field_elements<F: PrimeField>(xs: Vec<F>) -> Vec<u8> {
    xs.into_iter().flat_map(decode).collect()
}

/// Converts each chunk of size `n` from `bytes` to a field element
fn encode_as_field_elements_aux<F: PrimeField>(n: usize, bytes: &[u8]) -> Vec<F> {
    bytes
        .chunks(n)
        .map(|chunk| {
            if chunk.len() == n {
                encode(chunk)
            } else {
                // chunck.len() < n, this is the last chunk; we encode the
                // corresponding bytes padded with zeroes
                let bytes: Vec<_> = chunk.iter().copied().chain(repeat(0)).take(n).collect();
                encode(&bytes)
            }
        })
        .collect()
}

/// Converts each chunk of size `F::MODULUS_BIT_SIZE / 8` from `bytes` to a field element
pub fn encode_as_field_elements<F: PrimeField>(bytes: &[u8]) -> Vec<F> {
    encode_as_field_elements_aux(encoding_size::<F>(), bytes)
}

/// Converts each chunk of size `F::size_in_bytes()` from `bytes` to a field element
pub fn encode_as_field_elements_full<F: PrimeField>(bytes: &[u8]) -> Vec<F> {
    encode_as_field_elements_aux(encoding_size_full::<F>(), bytes)
}

/// Same as [encode_as_field_elements], but the returned vector is divided in
/// chunks of `domain_size` (except for the last chunk if its size is smaller)
pub fn encode_for_domain<F: PrimeField>(domain_size: usize, bytes: &[u8]) -> Vec<Vec<F>> {
    let xs = encode_as_field_elements(bytes);
    xs.chunks(domain_size)
        .map(|chunk| {
            if chunk.len() == domain_size {
                chunk.to_vec()
            } else {
                // chunk.len() < domain_size: this is the last chunk that needs
                // to be padded
                let mut padded_chunk = Vec::with_capacity(domain_size);
                padded_chunk.extend_from_slice(chunk);
                padded_chunk.resize(domain_size, F::zero());
                padded_chunk
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
    use ark_std::UniformRand;
    use mina_curves::pasta::Fp;
    use once_cell::sync::Lazy;
    use proptest::prelude::*;

    use crate::utils::test_utils::UserData;

    proptest! {
        // Check that the different decoding functions output the same result for the same input
        #[test]
        fn test_decodes_consistency(xs in any::<[u8;31]>())
          { let n : Fp = encode(&xs);
            let y_full : [u8; 31] = decode_full(n).as_slice()[1..32].try_into().unwrap();
            let y = decode(n);
            prop_assert_eq!(y_full, y.as_slice());
          }

        // Check that [u8] -> Fp -> [u8] is the identity function.
        #[test]
        fn test_round_trip_from_bytes(xs in any::<[u8;31]>())
          { let n : Fp = encode(&xs);
            let ys : [u8; 31] = decode_full(n).as_slice()[1..32].try_into().unwrap();
            prop_assert_eq!(xs, ys);
          }

        // Check that Fp -> [u8] -> Fp is the identity function.
        #[test]
        fn test_round_trip_from_fp(
            x in prop::strategy::Just(Fp::rand(&mut ark_std::rand::thread_rng()))
        ) {
            let bytes = decode_full(x);
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
