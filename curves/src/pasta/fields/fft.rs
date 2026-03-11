use ark_ff::biginteger::BigInteger;

/// A trait that defines parameters for a field that can be used for FFTs.
pub trait FftParameters: 'static + Send + Sync + Sized {
    type BigInt: BigInteger;

    /// Let `N` be the size of the multiplicative group defined by the field.
    /// Then `TWO_ADICITY` is the two-adicity of `N`, i.e. the integer `s`
    /// such that `N = 2^s * t` for some odd integer `t`.
    const TWO_ADICITY: u32;

    /// 2^s root of unity computed by GENERATOR^t
    const TWO_ADIC_ROOT_OF_UNITY: Self::BigInt;

    /// An integer `b` such that there exists a multiplicative subgroup
    /// of size `b^k` for some integer `k`.
    const SMALL_SUBGROUP_BASE: Option<u32> = None;

    /// The integer `k` such that there exists a multiplicative subgroup
    /// of size `Self::SMALL_SUBGROUP_BASE^k`.
    const SMALL_SUBGROUP_BASE_ADICITY: Option<u32> = None;

    /// `GENERATOR^((MODULUS-1) / (2^s *`
    /// `SMALL_SUBGROUP_BASE^SMALL_SUBGROUP_BASE_ADICITY))` Used for mixed-radix FFT.
    const LARGE_SUBGROUP_ROOT_OF_UNITY: Option<Self::BigInt> = None;
}

/// A trait that defines parameters for a prime field.
pub trait FpParameters: FftParameters {
    /// The modulus of the field.
    const MODULUS: Self::BigInt;

    /// The number of bits needed to represent the `Self::MODULUS`.
    const MODULUS_BITS: u32;

    /// The number of bits that must be shaved from the beginning of
    /// the representation when randomly sampling.
    const REPR_SHAVE_BITS: u32;

    /// Let `M` be the power of 2^64 nearest to `Self::MODULUS_BITS`. Then
    /// `R = M % Self::MODULUS`.
    const R: Self::BigInt;

    /// R2 = R^2 % `Self::MODULUS`
    const R2: Self::BigInt;

    /// INV = -MODULUS^{-1} mod 2^64
    const INV: u64;

    /// A multiplicative generator of the field.
    /// `Self::GENERATOR` is an element having multiplicative order
    /// `Self::MODULUS - 1`.
    const GENERATOR: Self::BigInt;

    /// The number of bits that can be reliably stored.
    /// (Should equal `SELF::MODULUS_BITS - 1`)
    const CAPACITY: u32;

    /// t for 2^s * t = MODULUS - 1, and t coprime to 2.
    const T: Self::BigInt;

    /// (t - 1) / 2
    const T_MINUS_ONE_DIV_TWO: Self::BigInt;

    /// (`Self::MODULUS` - 1) / 2
    const MODULUS_MINUS_ONE_DIV_TWO: Self::BigInt;
}

pub trait Fp256Parameters {}
