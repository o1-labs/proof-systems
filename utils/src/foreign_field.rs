use ark_ff::FftField;
use num_bigint::BigUint;

const LIMB_BITS: usize = 88;

/// Split a foreign field element into a vector of `LIMB_BITS`-bit field elements of type `F`
pub fn foreign_field_element_to_limbs<F: FftField>(modulus: BigUint) -> Vec<F> {
    let bytes = modulus.to_bytes_le();
    let chunks: Vec<&[u8]> = bytes
        .chunks(LIMB_BITS / 8)
        .collect();
    chunks
        .iter()
        .map(|chunk| F::from_random_bytes(chunk).expect("failed to deserialize"))
        .collect()
}
