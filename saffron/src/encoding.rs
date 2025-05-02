use crate::ScalarField;
use o1_utils::FieldHelpers;
use ark_ff::{BigInteger, PrimeField};

pub fn encode<Fp: PrimeField>(bytes: &[u8]) -> Fp {
    Fp::from_le_bytes_mod_order(bytes)
}

pub fn decode_into<Fp: PrimeField>(buffer: &mut [u8], x: Fp) {
    let bytes = x.into_bigint().to_bytes_le();
    buffer.copy_from_slice(&bytes);
}

pub fn decode_into_vec<Fp: PrimeField>(x: Fp) -> Vec<u8> {
    x.into_bigint().to_bytes_le()
}

pub fn encode_as_field_elements<F: PrimeField>(bytes: &[u8]) -> Vec<F> {
    let n = ((F::MODULUS_BIT_SIZE / 8) + 1) as usize;
    bytes
        .chunks(n)
        .map(|chunk| {
            let mut bytes = vec![0u8; n];
            bytes[..chunk.len()].copy_from_slice(chunk);
            encode(&bytes)
        })
        .collect::<Vec<_>>()
}

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

pub 
fn decode_from_field_elements<F: PrimeField>(xs: Vec<F>) -> Vec<u8> {
    let mut buffer = vec![0u8; F::size_in_bytes()];
    xs.iter()
        .flat_map(|x| {
            decode_into(&mut buffer, *x);
            buffer[0..F::size_in_bytes()].to_vec()
        })
        .collect()
}

/// Converts a bytes vector into a vector of vectors of scalars,
/// where each vector of scalars is of size [srs_size]
pub fn scalars_from_bytes(bytes: &[u8]) -> Vec<ScalarField> {
    encode_as_field_elements(bytes)
}

pub fn scalar_to_bytes(x: ScalarField) -> Vec<u8> {
    decode_into_vec(x)
}
