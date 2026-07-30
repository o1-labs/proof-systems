use super::fft::{FftParameters, Fp256Parameters};
use ark_ff::{
    biginteger::BigInteger256 as BigInteger,
    fields::{MontBackend, MontConfig},
    Fp256,
};
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
    OpenVmFpMod { modulus = "28948022309329048855892746252171976963363056481941560715954676764349967630337" }
}

#[derive(MontConfig)]
#[modulus = "28948022309329048855892746252171976963363056481941560715954676764349967630337"]
#[generator = "5"]
pub struct FqConfigDerived;

#[cfg(not(any(feature = "sp1", feature = "openvm")))]
pub use FqConfigDerived as FqConfig;

#[cfg(any(feature = "sp1", feature = "openvm"))]
pub struct FqConfig;

#[cfg(any(feature = "sp1", feature = "openvm"))]
impl MontConfig<4> for FqConfig {
    const MODULUS: BigInt<4> = <FqConfigDerived as MontConfig<4>>::MODULUS;

    const GENERATOR: Fp256<MontBackend<Self, 4>> =
        Fp256::new_unchecked(<FqConfigDerived as MontConfig<4>>::GENERATOR.0);

    const TWO_ADIC_ROOT_OF_UNITY: Fp256<MontBackend<Self, 4>> =
        Fp256::new_unchecked(<FqConfigDerived as MontConfig<4>>::TWO_ADIC_ROOT_OF_UNITY.0);

    // SP1 zkVM precompile path: replace Montgomery multiplication with two
    // sys_bigint calls — `a·b mod m` followed by multiplication by R⁻¹ to
    // strip the extra factor of R introduced when the inputs are already
    // in Montgomery form. R_INV is precomputed for this modulus.
    #[cfg(all(target_os = "zkvm", feature = "sp1"))]
    #[inline(always)]
    fn mul_assign(
        a: &mut Fp256<MontBackend<Self, 4>>,
        b: &Fp256<MontBackend<Self, 4>>,
    ) {
        // R_INV = (2^256)^-1 mod MODULUS, little-endian u64 limbs.
        const R_INV: [u64; 4] = [
            0xcf3f8e8753a769a9,
            0xac9fba6a4077fc57,
            0x70cb2996efc89a65,
            0x21f1c4ff1e2278d5,
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

    // Σ aᵢ · bᵢ on Montgomery-form inputs. Each sys_bigint of two
    // Montgomery values yields aᵢ·bᵢ·R² mod m; summing those still in
    // R²-scale and applying *R⁻¹ once at the end gives the Montgomery
    // product of the sum. That's M + 1 precompile calls instead of 2M
    // for the naive `.map().sum()` over `mul_assign`.
    #[cfg(all(target_os = "zkvm", feature = "sp1"))]
    #[inline]
    fn sum_of_products<const M: usize>(
        a: &[Fp256<MontBackend<Self, 4>>; M],
        b: &[Fp256<MontBackend<Self, 4>>; M],
    ) -> Fp256<MontBackend<Self, 4>> {
        // Same value as mul_assign's R_INV.
        const R_INV: [u64; 4] = [
            0xcf3f8e8753a769a9,
            0xac9fba6a4077fc57,
            0x70cb2996efc89a65,
            0x21f1c4ff1e2278d5,
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
        const R_INV: [u64; 4] = [0xcf3f8e8753a769a9,
            0xac9fba6a4077fc57,
            0x70cb2996efc89a65,
            0x21f1c4ff1e2278d5];
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
        const R_INV: [u64; 4] = [0xcf3f8e8753a769a9,
            0xac9fba6a4077fc57,
            0x70cb2996efc89a65,
            0x21f1c4ff1e2278d5];
        let mut acc = OpenVmFpMod::ZERO;
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
fn limbs_to_mod(limbs: &[u64; 4]) -> OpenVmFpMod {
    use openvm_algebra_guest::IntMod;
    let mut bytes = [0u8; 32];
    for (i, limb) in limbs.iter().enumerate() {
        bytes[i * 8..(i + 1) * 8].copy_from_slice(&limb.to_le_bytes());
    }
    OpenVmFpMod::from_le_bytes_unchecked(&bytes)
}

#[cfg(all(target_os = "zkvm", feature = "openvm"))]
#[inline(always)]
fn mod_to_limbs(x: &OpenVmFpMod) -> [u64; 4] {
    use openvm_algebra_guest::IntMod;
    let bytes = x.as_le_bytes();
    let mut limbs = [0u64; 4];
    for (i, limb) in limbs.iter_mut().enumerate() {
        *limb = u64::from_le_bytes(bytes[i * 8..(i + 1) * 8].try_into().unwrap());
    }
    limbs
}
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
