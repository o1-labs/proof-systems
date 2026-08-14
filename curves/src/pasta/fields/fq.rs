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
#[cfg(all(any(target_os = "zkvm", target_os = "openvm"), feature = "openvm"))]
openvm_algebra_guest::moduli_macros::moduli_declare! {
    OpenVmFqMod { modulus = "28948022309329048855892746252171976963363056481941647379679742748393362948097" }
}

#[derive(MontConfig)]
#[modulus = "28948022309329048855892746252171976963363056481941647379679742748393362948097"]
#[generator = "5"]
pub struct FrConfigDerived;

// These three gates said `sp1` alone, which silently disabled the whole OpenVM
// path for Fq: `FrConfig` resolved to the derived config, and the `openvm`
// `mul_assign` below — correctly gated in itself — sat inside an impl block that
// was never compiled. Fq is Vesta's base field and Pallas's scalar field, so
// that is every coordinate conversion on the chip boundary running on arkworks'
// software Montgomery multiplication. `fp.rs` had the right gate all along;
// this is fq.rs catching up.
#[cfg(not(any(feature = "sp1", feature = "openvm")))]
pub use FrConfigDerived as FrConfig;

#[cfg(any(feature = "sp1", feature = "openvm"))]
pub struct FrConfig;

#[cfg(any(feature = "sp1", feature = "openvm"))]
impl MontConfig<4> for FrConfig {
    const MODULUS: BigInt<4> = <FrConfigDerived as MontConfig<4>>::MODULUS;

    // Canonical storage under OpenVM. See the long comment in `fp.rs`: `R = 1`
    // makes `ONE` canonical, and `R2 = 2²⁵⁶ mod q` is what the const path behind
    // `MontFp!` needs to stay the identity.
    #[cfg(all(any(target_os = "zkvm", target_os = "openvm"), feature = "openvm"))]
    const R: BigInt<4> = BigInt::one();

    #[cfg(all(any(target_os = "zkvm", target_os = "openvm"), feature = "openvm"))]
    const R2: BigInt<4> = Self::MODULUS.montgomery_r();

    #[cfg(all(any(target_os = "zkvm", target_os = "openvm"), feature = "openvm"))]
    const GENERATOR: Fp256<MontBackend<Self, 4>> = ark_ff::MontFp!("5");

    #[cfg(all(any(target_os = "zkvm", target_os = "openvm"), feature = "openvm"))]
    const TWO_ADIC_ROOT_OF_UNITY: Fp256<MontBackend<Self, 4>> = ark_ff::MontFp!(
        "20761624379169977859705911634190121761503565370703356079647768903521299517535"
    );

    #[cfg(not(all(any(target_os = "zkvm", target_os = "openvm"), feature = "openvm")))]
    const GENERATOR: Fp256<MontBackend<Self, 4>> =
        Fp256::new_unchecked(<FrConfigDerived as MontConfig<4>>::GENERATOR.0);

    #[cfg(not(all(any(target_os = "zkvm", target_os = "openvm"), feature = "openvm")))]
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
    // OpenVM modular-extension path, on canonical values (see `R` / `R2` above,
    // and `fp.rs` for the full reasoning). `IntMod`'s `*` on canonical inputs is
    // already the answer: one chip instruction, where Montgomery storage needed
    // two.
    //
    // `from_le_bytes_unchecked` skips the reduction check. That is sound here:
    // arkworks maintains `value < MODULUS` as an invariant on every `Fp256`, and
    // canonical values are exactly the residues below the modulus. Do not reuse
    // this on values from outside the field.
    #[cfg(all(any(target_os = "zkvm", target_os = "openvm"), feature = "openvm"))]
    #[inline(always)]
    fn mul_assign(a: &mut Fp256<MontBackend<Self, 4>>, b: &Fp256<MontBackend<Self, 4>>) {
        let out = &limbs_to_mod(&(a.0).0) * &limbs_to_mod(&(b.0).0);
        (a.0).0 = mod_to_limbs(&out);
    }

    #[cfg(all(any(target_os = "zkvm", target_os = "openvm"), feature = "openvm"))]
    #[inline(always)]
    fn square_in_place(a: &mut Fp256<MontBackend<Self, 4>>) {
        let b = *a;
        Self::mul_assign(a, &b);
    }

    // Σ aᵢ·bᵢ in M chip multiplies; canonical values accumulate directly, with
    // no final rescaling by R⁻¹.
    #[cfg(all(any(target_os = "zkvm", target_os = "openvm"), feature = "openvm"))]
    #[inline]
    fn sum_of_products<const M: usize>(
        a: &[Fp256<MontBackend<Self, 4>>; M],
        b: &[Fp256<MontBackend<Self, 4>>; M],
    ) -> Fp256<MontBackend<Self, 4>> {
        use openvm_algebra_guest::IntMod;
        let mut acc = OpenVmFqMod::ZERO;
        for i in 0..M {
            acc += &limbs_to_mod(&(a[i].0).0) * &limbs_to_mod(&(b[i].0).0);
        }
        Fp256::<MontBackend<Self, 4>>::new_unchecked(BigInt::new(mod_to_limbs(&acc)))
    }

    // One `DivMod` chip instruction instead of arkworks' software extended
    // Euclid. `div_unsafe` is UB on a zero denominator, which the zero check
    // rules out — and which is the `None` arm of the contract anyway.
    #[cfg(all(any(target_os = "zkvm", target_os = "openvm"), feature = "openvm"))]
    #[inline(always)]
    fn inverse(a: &Fp256<MontBackend<Self, 4>>) -> Option<Fp256<MontBackend<Self, 4>>> {
        use ark_ff::Zero;
        use openvm_algebra_guest::{DivUnsafe, IntMod};
        if a.is_zero() {
            return None;
        }
        let out = OpenVmFqMod::ONE.div_unsafe(&limbs_to_mod(&(a.0).0));
        Some(Fp256::<MontBackend<Self, 4>>::new_unchecked(BigInt::new(
            mod_to_limbs(&out),
        )))
    }

    // Canonical storage makes both conversions moves rather than a Montgomery
    // reduction and a multiply by R2.
    #[cfg(all(any(target_os = "zkvm", target_os = "openvm"), feature = "openvm"))]
    #[inline(always)]
    fn into_bigint(a: Fp256<MontBackend<Self, 4>>) -> BigInt<4> {
        a.0
    }

    #[cfg(all(any(target_os = "zkvm", target_os = "openvm"), feature = "openvm"))]
    #[inline(always)]
    fn from_bigint(r: BigInt<4>) -> Option<Fp256<MontBackend<Self, 4>>> {
        if r >= Self::MODULUS {
            None
        } else {
            Some(Fp256::<MontBackend<Self, 4>>::new_unchecked(r))
        }
    }
}

/// arkworks' little-endian `[u64; 4]` -> the extension's modular type.
///
/// See `fp.rs` for why this is a `bytemuck` reinterpretation rather than a
/// hand-rolled byte loop: same bytes, same order, and the conversion runs three
/// times per multiplication against a single chip instruction.
#[cfg(all(any(target_os = "zkvm", target_os = "openvm"), feature = "openvm"))]
#[inline(always)]
fn limbs_to_mod(limbs: &[u64; 4]) -> OpenVmFqMod {
    use openvm_algebra_guest::IntMod;
    let bytes: &[u8; 32] = bytemuck::cast_ref(limbs);
    OpenVmFqMod::from_le_bytes_unchecked(bytes)
}

#[cfg(all(any(target_os = "zkvm", target_os = "openvm"), feature = "openvm"))]
#[inline(always)]
fn mod_to_limbs(x: &OpenVmFqMod) -> [u64; 4] {
    use openvm_algebra_guest::IntMod;
    bytemuck::pod_read_unaligned(x.as_le_bytes())
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
