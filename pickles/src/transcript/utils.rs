use ark_ff::{BigInteger, FftField, FpParameters, PrimeField};

pub(super) fn need_decompose<Fp: PrimeField, Fr: PrimeField>() -> bool {
    let fp_mod = Fp::Params::MODULUS.into();
    let fr_mod = Fr::Params::MODULUS.into();
    debug_assert!(2u64 * fp_mod.clone() > fr_mod.clone());
    debug_assert!(2u64 * fr_mod.clone() > fp_mod.clone());
    fp_mod < fr_mod
}

pub(super) fn transfer_hash<Fp: PrimeField, Fr: PrimeField>(e: Fr) -> Fp {
    debug_assert!(!need_decompose::<Fp, Fr>());
    let bits: Vec<bool> = e.into_repr().to_bits_le();
    Fp::from_repr(Fp::BigInt::from_bits_le(&bits)).unwrap()
}

// a direct lift is possible
pub(super) fn lift<Fp: PrimeField, Fr: PrimeField>(e: Fr) -> Fp {
    debug_assert!(!need_decompose::<Fp, Fr>());
    let bits: Vec<bool> = e.into_repr().to_bits_le();
    Fp::from_repr(Fp::BigInt::from_bits_le(&bits)).unwrap()
}

// a decomposition is needed
pub(super) fn decompose<Fp: PrimeField, Fr: PrimeField>(e: Fr) -> [Fp; 2] {
    debug_assert!(need_decompose::<Fp, Fr>());

    let bits: Vec<bool> = e.into_repr().to_bits_le();

    [
        Fp::from_repr(Fp::BigInt::from_bits_le(&bits[1..bits.len()])).unwrap(),
        if bits[0] { Fp::one() } else { Fp::zero() },
    ]
}
