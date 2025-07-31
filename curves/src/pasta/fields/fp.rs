use super::fft::{FftParameters, Fp256Parameters};
use ark_ff::{
    Field,
    biginteger::BigInteger256 as BigInteger,
    fields::{MontBackend, MontConfig},
    Fp256,
};

#[derive(MontConfig)]
#[modulus = "28948022309329048855892746252171976963363056481941560715954676764349967630337"]
#[generator = "5"]
pub struct FqConfig;
pub type Fp = Fp256<MontBackend<FqConfig, 4>>;

pub struct FpParameters;

impl Fp256Parameters for FpParameters {}

impl FftParameters for FpParameters {
    type BigInt = BigInteger;

    const TWO_ADICITY: u32 = 32;

    #[rustfmt::skip]
    const TWO_ADIC_ROOT_OF_UNITY: BigInteger = BigInteger::new([
        0xa28db849bad6dbf0, 0x9083cd03d3b539df, 0xfba6b9ca9dc8448e, 0x3ec928747b89c6da
    ]);
}

impl super::fft::FpParameters for FpParameters {
    // 28948022309329048855892746252171976963363056481941560715954676764349967630337
    const MODULUS: BigInteger = BigInteger::new([
        0x992d30ed00000001,
        0x224698fc094cf91b,
        0x0,
        0x4000000000000000,
    ]);

    const R: BigInteger = BigInteger::new([
        0x34786d38fffffffd,
        0x992c350be41914ad,
        0xffffffffffffffff,
        0x3fffffffffffffff,
    ]);

    const R2: BigInteger = BigInteger::new([
        0x8c78ecb30000000f,
        0xd7d30dbd8b0de0e7,
        0x7797a99bc3c95d18,
        0x96d41af7b9cb714,
    ]);

    const MODULUS_MINUS_ONE_DIV_TWO: BigInteger = BigInteger::new([
        0xcc96987680000000,
        0x11234c7e04a67c8d,
        0x0,
        0x2000000000000000,
    ]);

    // T and T_MINUS_ONE_DIV_TWO, where MODULUS - 1 = 2^S * T
    const T: BigInteger = BigInteger::new([0x94cf91b992d30ed, 0x224698fc, 0x0, 0x40000000]);

    const T_MINUS_ONE_DIV_TWO: BigInteger =
        BigInteger::new([0x4a67c8dcc969876, 0x11234c7e, 0x0, 0x20000000]);

    // GENERATOR = 5
    const GENERATOR: BigInteger = BigInteger::new([
        0xa1a55e68ffffffed,
        0x74c2a54b4f4982f3,
        0xfffffffffffffffd,
        0x3fffffffffffffff,
    ]);

    const MODULUS_BITS: u32 = 255;

    const CAPACITY: u32 = Self::MODULUS_BITS - 1;

    const REPR_SHAVE_BITS: u32 = 1;

    // -(MODULUS^{-1} mod 2^64) mod 2^64
    const INV: u64 = 11037532056220336127;
}

impl crate::pasta::wasm_friendly::MinimalField for Fp {
    fn square_in_place(&mut self) -> &mut Self {
        <Fp as Field>::square_in_place(self)
    }
}
