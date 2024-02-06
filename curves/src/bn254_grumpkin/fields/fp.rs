//! Scalar field of BN254
//! Copy from <https://github.com/arkworks-rs/curves/blob/v0.3.0/bn254/src/fields/fr.rs>

use ark_ff::{biginteger::BigInteger256 as BigInteger, fields::*};

pub type Fp = Fp256<FpParameters>;

pub struct FpParameters;

impl Fp256Parameters for FpParameters {}
impl FftParameters for FpParameters {
    type BigInt = BigInteger;

    const TWO_ADICITY: u32 = 28;

    #[rustfmt::skip]
    const TWO_ADIC_ROOT_OF_UNITY: BigInteger = BigInteger([
        7164790868263648668u64,
        11685701338293206998u64,
        6216421865291908056u64,
        1756667274303109607u64,
    ]);
}
impl ark_ff::FpParameters for FpParameters {
    /// MODULUS = 21888242871839275222246405745257275088548364400416034343698204186575808495617
    #[rustfmt::skip]
    const MODULUS: BigInteger = BigInteger([
        4891460686036598785u64,
        2896914383306846353u64,
        13281191951274694749u64,
        3486998266802970665u64,
    ]);

    const MODULUS_BITS: u32 = 254;

    const CAPACITY: u32 = Self::MODULUS_BITS - 1;

    const REPR_SHAVE_BITS: u32 = 2;

    /// R = pow(2, 320) % MODULUS
    ///   = 6350874878119819312338956282401532410528162663560392320966563075034087161851
    #[rustfmt::skip]
    const R: BigInteger = BigInteger([
        12436184717236109307u64,
        3962172157175319849u64,
        7381016538464732718u64,
        1011752739694698287u64,
    ]);

    /// R2 = R * R % MODULUS
    ///    = 944936681149208446651664254269745548490766851729442924617792859073125903783
    #[rustfmt::skip]
    const R2: BigInteger = BigInteger([
        1997599621687373223u64,
        6052339484930628067u64,
        10108755138030829701u64,
        150537098327114917u64,
    ]);

    /// INV = (-MODULUS) ^ {-1} % pow(2, 64) = 14042775128853446655
    const INV: u64 = 14042775128853446655u64;

    /// GENERATOR = 5
    #[rustfmt::skip]
    const GENERATOR: BigInteger = BigInteger([
        1949230679015292902u64,
        16913946402569752895u64,
        5177146667339417225u64,
        1571765431670520771u64,
    ]);

    /// (MODULUS - 1)/2 =
    /// 10944121435919637611123202872628637544274182200208017171849102093287904247808
    #[rustfmt::skip]
    const MODULUS_MINUS_ONE_DIV_TWO: BigInteger = BigInteger([
        0xa1f0fac9f8000000,
        0x9419f4243cdcb848,
        0xdc2822db40c0ac2e,
        0x183227397098d014,
    ]);

    // T and T_MINUS_ONE_DIV_TWO, where r - 1 = 2^s * t

    /// T = (MODULUS - 1) / 2^s =
    /// 81540058820840996586704275553141814055101440848469862132140264610111
    #[rustfmt::skip]
    const T: BigInteger = BigInteger([
        0x9b9709143e1f593f,
        0x181585d2833e8487,
        0x131a029b85045b68,
        0x30644e72e,
    ]);

    /// (T - 1) / 2 =
    /// 40770029410420498293352137776570907027550720424234931066070132305055
    #[rustfmt::skip]
    const T_MINUS_ONE_DIV_TWO: BigInteger = BigInteger([
        0xcdcb848a1f0fac9f,
        0x0c0ac2e9419f4243,
        0x098d014dc2822db4,
        0x183227397,
    ]);
}
