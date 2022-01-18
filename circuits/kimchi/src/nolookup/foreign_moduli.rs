//
// Foreign moduli helper
//
use ark_ec::AffineCurve;
use ark_ff::{BigInteger, FftField, FpParameters, PrimeField};
use mina_curves::pasta;
type PallasBaseField = <pasta::pallas::Affine as AffineCurve>::BaseField;
type VestaBaseField = <pasta::vesta::Affine as AffineCurve>::BaseField;

fn pack_modulus<N: FftField>(modulus: impl BigInteger) -> Vec<N> {
    let bytes = modulus.to_bytes_le();
    let chunks: Vec<&[u8]> = bytes
        .chunks(<N::BasePrimeField as PrimeField>::size_in_bits() / 8)
        .collect();
    chunks
        .iter()
        .map(|chunk| N::from_random_bytes(chunk).expect("failed to deserialize"))
        .collect()
}

pub fn get_modulus<N: FftField, F: PrimeField>() -> Vec<N> {
    pack_modulus(F::Params::MODULUS)
}

pub fn get_all<N: FftField>() -> Vec<Vec<N>> {
    vec![
        get_modulus::<N, PallasBaseField>(),
        get_modulus::<N, VestaBaseField>(),
    ]
}
