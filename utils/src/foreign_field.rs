use crate::field_helpers::FieldHelpers;
use ark_ff::FftField;
use num_bigint::BigUint;

pub const LIMB_BITS: u64 = 88;

/// Split a foreign field element into a vector of `LIMB_BITS` bits field elements of type `F` in little-endian
pub fn foreign_field_element_to_limbs<F: FftField>(fe: BigUint) -> Vec<F> {
    let bytes = fe.to_bytes_le();
    let chunks: Vec<&[u8]> = bytes.chunks((LIMB_BITS / 8).try_into().unwrap()).collect();
    chunks
        .iter()
        .map(|chunk| F::from_random_bytes(chunk).expect("failed to deserialize"))
        .collect()
}

/// Obtains an array of length 3 of the limbs of a foreign field element
pub fn vec_to_limbs<F: FftField>(vec: &[F]) -> [F; 3] {
    let mut limbs = [F::zero(); 3];
    for (i, limb) in vec.iter().enumerate() {
        limbs[i] = *limb;
    }
    limbs
}

/// Build a [BigUint] number from a set of limbs in little-endian order
pub fn limbs_to_foreign_field_element<F: FftField>(limbs: &[F]) -> BigUint {
    let mut bytes = vec![];
    for limb in limbs {
        bytes.extend_from_slice(&limb.to_bytes());
    }
    BigUint::from_bytes_le(&bytes)
}
