use super::fft::{FftParameters, Fp256Parameters, FpParameters};
use ark_ff::{biginteger::BigInteger256 as BigInteger, Fp256};
pub struct FqParameters;

use ark_ff::fields::{MontBackend, MontConfig};

#[cfg(all(feature = "sp1", feature = "openvm"))]
compile_error!(
    "features `sp1` and `openvm` are mutually exclusive: each replaces Montgomery \
     multiplication with a different zkVM's intrinsic"
);

#[cfg(any(feature = "sp1", feature = "openvm"))]
use ark_ff::BigInt;

// The OpenVM modular-arithmetic extension needs the modulus declared at compile
// time; the *binary* then calls `openvm::init!()`, which emits the matching
// `moduli_init!` from its openvm.toml. Declaring in a library and initialising
// in the binary is the supported split (see openvm's own `k256` guest lib).
//
// The binary's openvm.toml MUST list this modulus under
// `[app_vm_config.modular] supported_moduli`, or the guest traps at the first
// modular op.
#[cfg(all(target_os = "zkvm", feature = "openvm"))]
openvm_algebra_guest::moduli_macros::moduli_declare! {
    OpenVmFqMod { modulus = "28948022309329048855892746252171976963363056481941647379679742748393362948097" }
}

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

    #[cfg(all(target_os = "zkvm", feature = "sp1"))]
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

    #[cfg(all(target_os = "zkvm", feature = "sp1"))]
    #[inline(always)]
    fn square_in_place(a: &mut Fp256<MontBackend<Self, 4>>) {
        let b = *a;
        Self::mul_assign(a, &b);
    }

    // See fp.rs for the math. M + 1 precompile calls instead of 2M.
    #[cfg(all(target_os = "zkvm", feature = "sp1"))]
    #[inline]
    fn sum_of_products<const M: usize>(
        a: &[Fp256<MontBackend<Self, 4>>; M],
        b: &[Fp256<MontBackend<Self, 4>>; M],
    ) -> Fp256<MontBackend<Self, 4>> {
        const R_INV: [u64; 4] = [
            0x6119a3dd8e1a6f7f,
            0xc68de1279dc601eb,
            0x5790be58c050df13,
            0x1f7a89dd17647953,
        ];
        let mut acc =
            Fp256::<MontBackend<Self, 4>>::new_unchecked(BigInt::new([0u64; 4]));
        for i in 0..M {
            let mut tmp = [0u64; 4];
            sp1_zkvm::syscalls::sys_bigint(
                &mut tmp,
                0,
                &(a[i].0).0,
                &(b[i].0).0,
                &Self::MODULUS.0,
            );
            acc += Fp256::<MontBackend<Self, 4>>::new_unchecked(BigInt::new(tmp));
        }
        let mut result = [0u64; 4];
        sp1_zkvm::syscalls::sys_bigint(
            &mut result,
            0,
            &(acc.0).0,
            &R_INV,
            &Self::MODULUS.0,
        );
        Fp256::<MontBackend<Self, 4>>::new_unchecked(BigInt::new(result))
    }
    // OpenVM modular-extension path. Same arithmetic identity as the SP1 path:
    // `IntMod`'s `*` is a plain modular multiply on canonical values, so two
    // Montgomery-form inputs give `a·b·R²`; one more multiply by R⁻¹ brings it
    // back to `a·b·R`, the Montgomery form of the product.
    //
    // The byte shuffling is free: arkworks stores `[u64; 4]` little-endian and
    // `IntMod` stores 32 bytes little-endian, so the two layouts coincide and
    // the casts below are reinterpretations, not conversions.
    //
    // `from_le_bytes_unchecked` skips the reduction check. That is sound here
    // and only here: arkworks maintains `value < MODULUS` as an invariant on
    // every `Fp256`, and R_INV is a constant below the modulus. Do not reuse
    // this on values from outside the field.
    #[cfg(all(target_os = "zkvm", feature = "openvm"))]
    #[inline(always)]
    fn mul_assign(a: &mut Fp256<MontBackend<Self, 4>>, b: &Fp256<MontBackend<Self, 4>>) {
        use openvm_algebra_guest::IntMod;
        // R_INV = (2^256)^-1 mod MODULUS, little-endian u64 limbs.
        const R_INV: [u64; 4] = [0x6119a3dd8e1a6f7f,
            0xc68de1279dc601eb,
            0x5790be58c050df13,
            0x1f7a89dd17647953];
        let prod = &limbs_to_mod(&(a.0).0) * &limbs_to_mod(&(b.0).0);
        let out = &prod * &limbs_to_mod(&R_INV);
        (a.0).0 = mod_to_limbs(&out);
    }

    #[cfg(all(target_os = "zkvm", feature = "openvm"))]
    #[inline(always)]
    fn square_in_place(a: &mut Fp256<MontBackend<Self, 4>>) {
        let b = *a;
        Self::mul_assign(a, &b);
    }

    // Σ aᵢ·bᵢ. Each product stays in R²-scale; summing there and applying R⁻¹
    // once at the end costs M + 1 modular multiplies instead of 2M.
    #[cfg(all(target_os = "zkvm", feature = "openvm"))]
    #[inline]
    fn sum_of_products<const M: usize>(
        a: &[Fp256<MontBackend<Self, 4>>; M],
        b: &[Fp256<MontBackend<Self, 4>>; M],
    ) -> Fp256<MontBackend<Self, 4>> {
        use openvm_algebra_guest::IntMod;
        const R_INV: [u64; 4] = [0x6119a3dd8e1a6f7f,
            0xc68de1279dc601eb,
            0x5790be58c050df13,
            0x1f7a89dd17647953];
        let mut acc = OpenVmFqMod::ZERO;
        for i in 0..M {
            acc += &limbs_to_mod(&(a[i].0).0) * &limbs_to_mod(&(b[i].0).0);
        }
        let out = &acc * &limbs_to_mod(&R_INV);
        Fp256::<MontBackend<Self, 4>>::new_unchecked(BigInt::new(mod_to_limbs(&out)))
    }
}

/// arkworks' little-endian `[u64; 4]` -> the extension's modular type.
/// Written as an explicit byte-wise conversion rather than a pointer cast: this
/// crate denies `unsafe_code`, and the explicit form assumes nothing about
/// memory layout. The cost is 32 byte copies against a chip call.
#[cfg(all(target_os = "zkvm", feature = "openvm"))]
#[inline(always)]
fn limbs_to_mod(limbs: &[u64; 4]) -> OpenVmFqMod {
    use openvm_algebra_guest::IntMod;
    let mut bytes = [0u8; 32];
    for (i, limb) in limbs.iter().enumerate() {
        bytes[i * 8..(i + 1) * 8].copy_from_slice(&limb.to_le_bytes());
    }
    OpenVmFqMod::from_le_bytes_unchecked(&bytes)
}

#[cfg(all(target_os = "zkvm", feature = "openvm"))]
#[inline(always)]
fn mod_to_limbs(x: &OpenVmFqMod) -> [u64; 4] {
    use openvm_algebra_guest::IntMod;
    let bytes = x.as_le_bytes();
    let mut limbs = [0u64; 4];
    for (i, limb) in limbs.iter_mut().enumerate() {
        *limb = u64::from_le_bytes(bytes[i * 8..(i + 1) * 8].try_into().unwrap());
    }
    limbs
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
