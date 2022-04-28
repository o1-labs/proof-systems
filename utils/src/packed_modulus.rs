//!
//! Modulus packing helper
//!

use ark_ff::{BigInteger, FftField, FpParameters, PrimeField};
use num_bigint::BigUint;

/// Get the modulus (as `BigUint`) for the field specified by type parameter `F`
pub fn get_modulus<F: PrimeField>() -> BigUint {
    let bytes = F::Params::MODULUS.to_bytes_le();
    BigUint::from_bytes_le(&bytes)
}

/// Pack the foreign `modulus` into a vector a field elements of type `F`
pub fn packed_modulus<F: FftField>(modulus: BigUint) -> Vec<F> {
    let bytes = modulus.to_bytes_le();
    let chunks: Vec<&[u8]> = bytes
        .chunks(<F::BasePrimeField as PrimeField>::size_in_bits() / 8)
        .collect();
    chunks
        .iter()
        .map(|chunk| F::from_random_bytes(chunk).expect("failed to deserialize"))
        .collect()
}
