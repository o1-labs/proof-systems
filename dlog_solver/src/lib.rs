use algebra::{
    fields::{FftParameters, Fp256, Fp384},
    FftField, Field, Fp256Parameters, Fp384Parameters, SquareRootField,
};

pub trait DetSquareRootField: FftField + SquareRootField {
    type DetSquareRootParams: DetSquareRootParameters;

    // Given
    // - an order p field F with p - 1 = t * 2^k, t odd, g an element of order 2^k in F,
    // - h : F
    // output (c, d) such that
    // h = c * g^d, where c is in the orthogonal complement of < g >
    fn pre_decompose(&self) -> (Self, u64) {
        let t_component: Self = pow2_pow(self.clone(), Self::FftParams::TWO_ADICITY as usize);
        let c = t_component.pow(Self::DetSquareRootParams::TWO_TO_TWO_ADICITY_INV.as_ref());
        let two_to_k_component = c.inverse().unwrap() * self;
        let d = two_adic_discrete_log(two_to_k_component);
        (c, d)
    }

    fn det_sqrt(&self) -> Option<Self> {
        self.sqrt().map(|x| {
            let (_, d1) = x.pre_decompose();
            let top_bit = d1 >> (Self::FftParams::TWO_ADICITY - 1);
            if top_bit == 0 {
                x
            } else {
                -x
            }
        })
    }
}

pub trait DetSquareRootParameters: FftParameters {
    const TWO_TO_TWO_ADICITY_INV: Self::BigInt;
}

pub fn decompose<F: DetSquareRootField>(h: &F) -> (F, u64) {
    let (c, d) = h.pre_decompose();
    (
        c.pow(F::DetSquareRootParams::TWO_TO_TWO_ADICITY_INV.as_ref()),
        d,
    )
}

pub fn in_orthogonal_complement<P: FftParameters + Fp256Parameters + DetSquareRootParameters>(
    h: Fp256<P>,
) -> bool {
    pow2_pow(h, P::TWO_ADICITY as usize).pow(P::TWO_TO_TWO_ADICITY_INV.as_ref()) == h
}

pub fn compose<P: FftParameters + Fp256Parameters + DetSquareRootParameters>(
    (c, d): (Fp256<P>, u64),
) -> Fp256<P> {
    let g: Fp256<P> = FftField::two_adic_root_of_unity();
    c.pow([1 << P::TWO_ADICITY]) * g.pow([d])
}

// Given
// - an order p field F with p - 1 = t * 2^e, t odd, g an element of order 2^e in F,
// - h in < g >
// output x such that
// h = g^x
//
// This uses [this algorithm](https://en.wikipedia.org/wiki/Pohlig%E2%80%93Hellman_algorithm)
pub fn two_adic_discrete_log<F: DetSquareRootField>(h: F) -> u64 {
    let e = F::FftParams::TWO_ADICITY as usize;
    let mut x: u64 = 0;
    assert!(e <= 64);
    let g: F = FftField::two_adic_root_of_unity();
    let g_inv = g.inverse().unwrap();

    // Invariant: this is equal to g_inv^x at every iteration
    let mut g_inv_to_x = F::one();
    // Invariant: this is equal to g_inv^{2^k} at iteration k
    let mut g_inv_to_two_to_k = g_inv;
    for k in 0..e {
        let h_k = pow2_pow(g_inv_to_x * h, e - 1 - k); // This should equal +/- 1
        if !h_k.is_one() {
            x |= 1 << k;
            g_inv_to_x *= g_inv_to_two_to_k;
        }
        g_inv_to_two_to_k.square_in_place();
    }

    x
}

// Compute x^{2^k}
fn pow2_pow<F: Field>(x: F, k: usize) -> F {
    let mut res = x;
    for _ in 0..k {
        res.square_in_place();
    }
    res
}

impl<P: FftParameters + Fp256Parameters + DetSquareRootParameters> DetSquareRootField for Fp256<P> {
    type DetSquareRootParams = P;
}

impl<P: FftParameters + Fp384Parameters + DetSquareRootParameters> DetSquareRootField for Fp384<P> {
    type DetSquareRootParams = P;
}

use algebra::biginteger::{BigInteger256, BigInteger384};
use algebra::tweedle::{FpParameters, FqParameters};

impl DetSquareRootParameters for FpParameters {
    const TWO_TO_TWO_ADICITY_INV: Self::BigInt =
        BigInteger256([0x3b3a6633d1897d83, 0xc93d5b, 0xf000000000000000, 0xe34ab16]);
}

impl DetSquareRootParameters for FqParameters {
    const TWO_TO_TWO_ADICITY_INV: Self::BigInt =
        BigInteger256([0x9b71de17e6d2d5a0, 0x296ee0, 0x8c00000000000000, 0x2ecc05e]);
}

impl DetSquareRootParameters for algebra::bn_382::FpParameters {
    const TWO_TO_TWO_ADICITY_INV: Self::BigInt = BigInteger384([0, 0, 0, 0, 0, 0]);
}

impl DetSquareRootParameters for algebra::bn_382::FqParameters {
    const TWO_TO_TWO_ADICITY_INV: Self::BigInt = BigInteger384([0, 0, 0, 0, 0, 0]);
}
