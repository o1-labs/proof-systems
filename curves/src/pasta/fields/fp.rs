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
#[cfg(all(any(target_os = "zkvm", target_os = "openvm"), feature = "openvm"))]
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

    // ------------------------------------------------------------------
    // OpenVM: canonical storage instead of Montgomery form.
    //
    // arkworks stores `aR mod p`. The chip's `IntMod` is canonical, so every
    // Montgomery-form multiplication costs TWO chip instructions: `a·b` gives
    // `abR²`, and a second multiply by `R⁻¹` brings it back to `abR`. Storing
    // canonical values makes it one — and makes `into_bigint`, which the chip
    // boundary calls on every coordinate and scalar, a move instead of a
    // 16-mac Montgomery reduction.
    //
    // Representation is chosen by two constants, and they do NOT get the same
    // value:
    //
    // * `R` is only read as `FpConfig::ONE = Fp::new_unchecked(R)`, so canonical
    //   ONE means `R = 1`.
    // * `R2` is read by the **const** constructor `Fp::new` — the one `MontFp!`
    //   expands to — as `mont_mul(e, R2) = e·R2·2⁻²⁵⁶`. That path is const
    //   arithmetic inside ark-ff and ignores every override below, so getting
    //   `e` out requires `R2 = 2²⁵⁶ mod p`, i.e. the value `R` has by default.
    //   The Pasta curve parameters (`COEFF_B`, the generators) are `MontFp!`
    //   literals, so this is what keeps them correct.
    //
    // The other `R2` reader, `from_bigint`, is overridden below, and the third,
    // the default `inverse`, is overridden too.
    //
    // Gated on the zkVM target, not just the feature: a host build with
    // `openvm` on keeps arkworks' software Montgomery multiplication, which
    // only agrees with Montgomery *storage*.
    #[cfg(all(any(target_os = "zkvm", target_os = "openvm"), feature = "openvm"))]
    const R: BigInt<4> = BigInt::one();

    #[cfg(all(any(target_os = "zkvm", target_os = "openvm"), feature = "openvm"))]
    const R2: BigInt<4> = Self::MODULUS.montgomery_r();

    // Canonical constants for the canonical representation. `MontFp!` is exactly
    // right here: with `R2` as set above its const path is the identity, so the
    // decimal literal lands in the limbs unchanged. `fp_canonical_constants`
    // pins both against the derived config.
    #[cfg(all(any(target_os = "zkvm", target_os = "openvm"), feature = "openvm"))]
    const GENERATOR: Fp256<MontBackend<Self, 4>> = ark_ff::MontFp!("5");

    #[cfg(all(any(target_os = "zkvm", target_os = "openvm"), feature = "openvm"))]
    const TWO_ADIC_ROOT_OF_UNITY: Fp256<MontBackend<Self, 4>> = ark_ff::MontFp!(
        "19814229590243028906643993866117402072516588566294623396325693409366934201135"
    );

    // Montgomery storage everywhere else — the SP1 path and host builds. These
    // are the original definitions: same representation as `FqConfigDerived`,
    // so the raw limbs carry over.
    #[cfg(not(all(any(target_os = "zkvm", target_os = "openvm"), feature = "openvm")))]
    const GENERATOR: Fp256<MontBackend<Self, 4>> =
        Fp256::new_unchecked(<FqConfigDerived as MontConfig<4>>::GENERATOR.0);

    #[cfg(not(all(any(target_os = "zkvm", target_os = "openvm"), feature = "openvm")))]
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
    // OpenVM modular-extension path, on canonical values (see `R` / `R2` above).
    // `IntMod`'s `*` is a plain modular multiply, which on canonical inputs is
    // already the answer: one chip instruction, where Montgomery storage needed
    // two (the product, then a multiply by R⁻¹ to strip the extra factor of R).
    //
    // The byte shuffling is free: arkworks stores `[u64; 4]` little-endian and
    // `IntMod` stores 32 bytes little-endian, so the two layouts coincide and
    // the conversions below are reinterpretations, not arithmetic.
    //
    // `from_le_bytes_unchecked` skips the reduction check. That is sound here:
    // arkworks maintains `value < MODULUS` as an invariant on every `Fp256`, and
    // the representation change does not weaken it — canonical values are
    // exactly the residues below the modulus. Do not reuse this on values from
    // outside the field.
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

    // Σ aᵢ·bᵢ in M chip multiplies. The Montgomery version needed M + 1: the
    // products accumulated in R²-scale and one final multiply by R⁻¹ brought the
    // sum back. Canonical values accumulate directly.
    #[cfg(all(any(target_os = "zkvm", target_os = "openvm"), feature = "openvm"))]
    #[inline]
    fn sum_of_products<const M: usize>(
        a: &[Fp256<MontBackend<Self, 4>>; M],
        b: &[Fp256<MontBackend<Self, 4>>; M],
    ) -> Fp256<MontBackend<Self, 4>> {
        use openvm_algebra_guest::IntMod;
        let mut acc = OpenVmFpMod::ZERO;
        for i in 0..M {
            acc += &limbs_to_mod(&(a[i].0).0) * &limbs_to_mod(&(b[i].0).0);
        }
        Fp256::<MontBackend<Self, 4>>::new_unchecked(BigInt::new(mod_to_limbs(&acc)))
    }

    // The modular extension has a division instruction (`ModArithBaseFunct7::
    // DivMod`), so an inverse is one chip call. arkworks' default is a binary
    // extended Euclid in software — hundreds of RISC-V instructions, each limb
    // operation crossing the memory chip.
    //
    // `div_unsafe` is undefined behaviour on a non-invertible denominator, hence
    // the zero check first — which is also the `None` arm of the contract.
    #[cfg(all(any(target_os = "zkvm", target_os = "openvm"), feature = "openvm"))]
    #[inline(always)]
    fn inverse(a: &Fp256<MontBackend<Self, 4>>) -> Option<Fp256<MontBackend<Self, 4>>> {
        use ark_ff::Zero;
        use openvm_algebra_guest::{DivUnsafe, IntMod};
        if a.is_zero() {
            return None;
        }
        let out = OpenVmFpMod::ONE.div_unsafe(&limbs_to_mod(&(a.0).0));
        Some(Fp256::<MontBackend<Self, 4>>::new_unchecked(BigInt::new(
            mod_to_limbs(&out),
        )))
    }

    // Canonical storage makes both conversions moves. The defaults are a
    // 16-mac Montgomery reduction and a multiply by R2 respectively — and
    // `into_bigint` is on the hot path twice over: every coordinate and every
    // scalar crossing into the curve chip goes through it.
    #[cfg(all(any(target_os = "zkvm", target_os = "openvm"), feature = "openvm"))]
    #[inline(always)]
    fn into_bigint(a: Fp256<MontBackend<Self, 4>>) -> BigInt<4> {
        a.0
    }

    // Keeps the range check the default performs: `from_bigint` is the entry
    // point for externally supplied values, and everything downstream — the
    // chip's `from_le_bytes_unchecked` included — assumes `value < MODULUS`.
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
/// Both sides are little-endian with the same 32 bytes in the same order, so
/// this is a reinterpretation. `bytemuck::cast_ref` performs it in safe Rust —
/// a Pod-to-Pod cast, no `unsafe` and no layout assumption of our own — which
/// matters because this crate denies `unsafe_code`.
///
/// What it removes is the intermediate buffer: the previous version built a
/// `[u8; 32]` limb by limb and then let `from_le_bytes_unchecked` copy it, so
/// every conversion paid a four-iteration loop plus a memcpy. Now it is the
/// memcpy alone. The conversion is *not* incidental — it happens three times per
/// multiplication, and the multiplication itself is one chip instruction.
#[cfg(all(any(target_os = "zkvm", target_os = "openvm"), feature = "openvm"))]
#[inline(always)]
fn limbs_to_mod(limbs: &[u64; 4]) -> OpenVmFpMod {
    use openvm_algebra_guest::IntMod;
    let bytes: &[u8; 32] = bytemuck::cast_ref(limbs);
    OpenVmFpMod::from_le_bytes_unchecked(bytes)
}

/// The extension's modular type -> arkworks' limbs.
///
/// `pod_read_unaligned` rather than `from_bytes`: it is one memcpy with no
/// alignment precondition and no panic path. (`OpenVmFpMod` is `align(32)` so a
/// borrowing cast would in fact succeed, but that is the macro's business, not
/// ours.) The previous version ran four `from_le_bytes` with a `try_into`
/// unwrap each.
#[cfg(all(any(target_os = "zkvm", target_os = "openvm"), feature = "openvm"))]
#[inline(always)]
fn mod_to_limbs(x: &OpenVmFpMod) -> [u64; 4] {
    use openvm_algebra_guest::IntMod;
    bytemuck::pod_read_unaligned(x.as_le_bytes())
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
