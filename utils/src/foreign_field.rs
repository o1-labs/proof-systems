use ark_ff::FftField;
use num_bigint::BigUint;

pub const LIMB_BITS: usize = 88;

/// Split a foreign field element into a vector of `LIMB_BITS` bits field elements of type `F`
pub fn foreign_field_element_to_limbs<F: FftField>(fe: BigUint) -> Vec<F> {
    let bytes = fe.to_bytes_le();
    let chunks: Vec<&[u8]> = bytes.chunks(LIMB_BITS / 8).collect();
    chunks
        .iter()
        .map(|chunk| F::from_random_bytes(chunk).expect("failed to deserialize"))
        .collect()
}
