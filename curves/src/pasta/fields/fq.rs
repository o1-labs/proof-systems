use super::fft::{FftParameters, Fp256Parameters, FpParameters};
use ark_ff::{biginteger::BigInteger256 as BigInteger, Fp256};
#[cfg(feature = "sp1")]
use ark_ff::BigInt;

pub struct FqParameters;

use ark_ff::fields::{MontBackend, MontConfig};

#[derive(MontConfig)]
#[modulus = "28948022309329048855892746252171976963363056481941647379679742748393362948097"]
#[generator = "5"]
pub struct FrConfigDerived;

#[cfg(not(feature = "sp1"))]
pub use FrConfigDerived as FrConfig;

#[cfg(feature = "sp1")]
pub struct FrConfig;

#[cfg(feature = "sp1")]
impl MontConfig<4> for FrConfig {
    const MODULUS: BigInt<4> = <FrConfigDerived as MontConfig<4>>::MODULUS;

    const GENERATOR: Fp256<MontBackend<Self, 4>> =
        Fp256::new_unchecked(<FrConfigDerived as MontConfig<4>>::GENERATOR.0);

    const TWO_ADIC_ROOT_OF_UNITY: Fp256<MontBackend<Self, 4>> =
        Fp256::new_unchecked(<FrConfigDerived as MontConfig<4>>::TWO_ADIC_ROOT_OF_UNITY.0);

    #[cfg(target_os = "zkvm")]
    #[inline(always)]
    fn mul_assign(
        a: &mut Fp256<MontBackend<Self, 4>>,
        b: &Fp256<MontBackend<Self, 4>>,
    ) {
        // R_INV = (2^256)^-1 mod MODULUS, little-endian u64 limbs.
        const R_INV: [u64; 4] = [
            0x6119a3dd8e1a6f7f,
            0xc68de1279dc601eb,
            0x5790be58c050df13,
            0x1f7a89dd17647953,
        ];
        let mut tmp = [0u64; 4];
        sp1_zkvm::syscalls::sys_bigint(
            &mut tmp,
            0,
            &(a.0).0,
            &(b.0).0,
            &Self::MODULUS.0,
        );
        sp1_zkvm::syscalls::sys_bigint(
            &mut (a.0).0,
            0,
            &tmp,
            &R_INV,
            &Self::MODULUS.0,
        );
    }

    #[cfg(target_os = "zkvm")]
    #[inline(always)]
    fn square_in_place(a: &mut Fp256<MontBackend<Self, 4>>) {
        let b = *a;
        Self::mul_assign(a, &b);
    }
}

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
