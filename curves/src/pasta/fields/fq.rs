use super::fft::{FftParameters, Fp256Parameters, FpParameters};
use ark_ff::{biginteger::BigInteger256 as BigInteger, Fp256, Field};

pub struct FqParameters;

use ark_ff::fields::{MontBackend, MontConfig};

#[derive(MontConfig)]
#[modulus = "28948022309329048855892746252171976963363056481941647379679742748393362948097"]
#[generator = "5"]
pub struct FrConfig;
pub type Fq = Fp256<MontBackend<FrConfig, 4>>;

impl Fp256Parameters for FqParameters {}

impl FftParameters for FqParameters {
    type BigInt = BigInteger;

    const TWO_ADICITY: u32 = 32;

    #[rustfmt::skip]
    const TWO_ADIC_ROOT_OF_UNITY: BigInteger = BigInteger::new([
        0x218077428c9942de, 0xcc49578921b60494, 0xac2e5d27b2efbee2, 0xb79fa897f2db056
    ]);
}

impl FpParameters for FqParameters {
    // 28948022309329048855892746252171976963363056481941647379679742748393362948097
    const MODULUS: BigInteger = BigInteger::new([
        0x8c46eb2100000001,
        0x224698fc0994a8dd,
        0x0,
        0x4000000000000000,
    ]);

    const R: BigInteger = BigInteger::new([
        0x5b2b3e9cfffffffd,
        0x992c350be3420567,
        0xffffffffffffffff,
        0x3fffffffffffffff,
    ]);

    const R2: BigInteger = BigInteger::new([
        0xfc9678ff0000000f,
        0x67bb433d891a16e3,
        0x7fae231004ccf590,
        0x96d41af7ccfdaa9,
    ]);

    const MODULUS_MINUS_ONE_DIV_TWO: BigInteger = BigInteger::new([
        0xc623759080000000,
        0x11234c7e04ca546e,
        0x0,
        0x2000000000000000,
    ]);

    // T and T_MINUS_ONE_DIV_TWO, where MODULUS - 1 = 2^S * T

    const T: BigInteger = BigInteger::new([0x994a8dd8c46eb21, 0x224698fc, 0x0, 0x40000000]);

    const T_MINUS_ONE_DIV_TWO: BigInteger =
        BigInteger::new([0x4ca546ec6237590, 0x11234c7e, 0x0, 0x20000000]);

    // GENERATOR = 5
    const GENERATOR: BigInteger = BigInteger::new([
        0x96bc8c8cffffffed,
        0x74c2a54b49f7778e,
        0xfffffffffffffffd,
        0x3fffffffffffffff,
    ]);

    const MODULUS_BITS: u32 = 255;

    const CAPACITY: u32 = Self::MODULUS_BITS - 1;

    const REPR_SHAVE_BITS: u32 = 1;

    // -(MODULUS^{-1} mod 2^64) mod 2^64
    const INV: u64 = 10108024940646105087;
}

impl crate::pasta::wasm_friendly::MinimalField for Fq {
    fn square_in_place(&mut self) -> &mut Self {
        <Fq as Field>::square_in_place(self)
    }
}
