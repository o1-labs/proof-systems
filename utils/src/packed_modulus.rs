//
// Foreign moduli helper
//
use ark_ff::{BigInteger, FftField, FpParameters, PrimeField};

pub fn packed_modulus<N: FftField, F: PrimeField>() -> Vec<N> {
    let bytes = F::Params::MODULUS.to_bytes_le();
    let chunks: Vec<&[u8]> = bytes
        .chunks(<N::BasePrimeField as PrimeField>::size_in_bits() / 8)
        .collect();
    chunks
        .iter()
        .map(|chunk| N::from_random_bytes(chunk).expect("failed to deserialize"))
        .collect()
}