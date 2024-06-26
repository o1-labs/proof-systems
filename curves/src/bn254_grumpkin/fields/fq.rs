//! Base field of BN254
//! Copy from <https://github.com/arkworks-rs/curves/blob/v0.3.0/bn254/src/fields/fq.rs>

use ark_ff::{biginteger::BigInteger256 as BigInteger, field_new, fields::*};

pub type Fq = Fp256<FqParameters>;

pub struct FqParameters;

impl Fp256Parameters for FqParameters {}
impl FftParameters for FqParameters {
    type BigInt = BigInteger;

    const TWO_ADICITY: u32 = 1;

    #[rustfmt::skip]
    const TWO_ADIC_ROOT_OF_UNITY: BigInteger = BigInteger([
        0x68c3488912edefaa,
        0x8d087f6872aabf4f,
        0x51e1a24709081231,
        0x2259d6b14729c0fa,
    ]);
}
impl ark_ff::FpParameters for FqParameters {
    /// MODULUS = 21888242871839275222246405745257275088696311157297823662689037894645226208583
    #[rustfmt::skip]
    const MODULUS: BigInteger = BigInteger([
        0x3c208c16d87cfd47,
        0x97816a916871ca8d,
        0xb85045b68181585d,
        0x30644e72e131a029,
    ]);

    const MODULUS_BITS: u32 = 254;

    const CAPACITY: u32 = Self::MODULUS_BITS - 1;

    const REPR_SHAVE_BITS: u32 = 2;

    #[rustfmt::skip]
    const R: BigInteger = BigInteger([
        0xd35d438dc58f0d9d,
        0x0a78eb28f5c70b3d,
        0x666ea36f7879462c,
        0xe0a77c19a07df2f,
    ]);

    #[rustfmt::skip]
    const R2: BigInteger = BigInteger([
        0xf32cfc5b538afa89,
        0xb5e71911d44501fb,
        0x47ab1eff0a417ff6,
        0x6d89f71cab8351f,
    ]);

    const INV: u64 = 9786893198990664585u64;

    // GENERATOR = 3
    #[rustfmt::skip]
    const GENERATOR: BigInteger = BigInteger([
        0x7a17caa950ad28d7,
        0x1f6ac17ae15521b9,
        0x334bea4e696bd284,
        0x2a1f6744ce179d8e,
    ]);

    #[rustfmt::skip]
    const MODULUS_MINUS_ONE_DIV_TWO: BigInteger = BigInteger([
        0x9e10460b6c3e7ea3,
        0xcbc0b548b438e546,
        0xdc2822db40c0ac2e,
        0x183227397098d014,
    ]);

    // T and T_MINUS_ONE_DIV_TWO, where MODULUS - 1 = 2^S * T

    // T = (MODULUS - 1) // 2^S =
    // 10944121435919637611123202872628637544348155578648911831344518947322613104291
    #[rustfmt::skip]
    const T: BigInteger = BigInteger([
        0x9e10460b6c3e7ea3,
        0xcbc0b548b438e546,
        0xdc2822db40c0ac2e,
        0x183227397098d014,
    ]);

    // (T - 1) // 2 =
    // 5472060717959818805561601436314318772174077789324455915672259473661306552145
    #[rustfmt::skip]
    const T_MINUS_ONE_DIV_TWO: BigInteger = BigInteger([
        0x4f082305b61f3f51,
        0x65e05aa45a1c72a3,
        0x6e14116da0605617,
        0xc19139cb84c680a,
    ]);
}

pub const FQ_ONE: Fq = field_new!(Fq, "1");
pub const FQ_ZERO: Fq = field_new!(Fq, "0");
