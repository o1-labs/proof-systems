use algebra::{
    fields::{FftParameters, Fp256},
    FftField, Field, Fp256Parameters, One, SquareRootField,
};

pub trait DetSquareRootField: FftField {
    fn det_sqrt(&self) -> Option<Self>;
}

pub trait DetSquareRootParameters: FftParameters {
    const TWO_TO_TWO_ADICITY_INV: Self::BigInt;
}

// Given
// - an order p field F with p - 1 = t * 2^k, t odd, g an element of order 2^k in F,
// - h : F
// output (c, d) such that
// h = c * g^d, where c is in the orthogonal complement of < g >
pub fn pre_decompose<P: FftParameters + Fp256Parameters + DetSquareRootParameters>(
    h: Fp256<P>,
) -> (Fp256<P>, u64) {
    let t_component: Fp256<P> = pow2_pow(h, P::TWO_ADICITY as usize);
    let c = t_component.pow(P::TWO_TO_TWO_ADICITY_INV.as_ref());
    let two_to_k_component = c.inverse().unwrap() * h;
    let d = two_adic_discrete_log(two_to_k_component);
    (c, d)
}

pub fn decompose<P: FftParameters + Fp256Parameters + DetSquareRootParameters>(
    h: Fp256<P>,
) -> (Fp256<P>, u64) {
    let (c, d) = pre_decompose(h);
    (c.pow(P::TWO_TO_TWO_ADICITY_INV.as_ref()), d)
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
pub fn two_adic_discrete_log<P: FftParameters + Fp256Parameters>(h: Fp256<P>) -> u64 {
    let e = P::TWO_ADICITY as usize;
    let mut x: u64 = 0;
    assert!(e <= 64);
    let g: Fp256<P> = FftField::two_adic_root_of_unity();
    let g_inv = g.inverse().unwrap();

    // Invariant: this is equal to g_inv^x at every iteration
    let mut g_inv_to_x = Fp256::<P>::one();
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
    fn det_sqrt(&self) -> Option<Self> {
        self.sqrt().map(|x| {
            let (_, d1) = pre_decompose::<P>(x);
            let top_bit = d1 >> (P::TWO_ADICITY - 1);
            if top_bit == 0 {
                x
            } else {
                -x
            }
        })
    }
}

// given c of order 2^k, generate a witness to check its order.
// The witness is cwitness = c^{(2^k)^-1 mod t}. This can be verified by checking
// k squarings of cwitness
fn witness_c_order<P: DetSquareRootParameters + Fp256Parameters>(c: Fp256<P>) -> Fp256<P> {
    c.pow(P::TWO_TO_TWO_ADICITY_INV.as_ref())
}

pub struct Witness_correct_sqrt<P: FftParameters + Fp256Parameters> {
    c: Fp256<P>,
    d: u64,
    c_inverse_order: Fp256<P>,
}

pub fn witness_det_sqrt<P: FftParameters + Fp256Parameters + DetSquareRootParameters>(
    b: Fp256<P>,
) -> Witness_correct_sqrt<P> {
    let (c, d): (Fp256<P>, u64) = decompose::<P>(b);
    let cwitness: Fp256<P> = witness_c_order::<P>(c);
    let witnesscd: Witness_correct_sqrt<P> = Witness_correct_sqrt::<P> {
        c: c,
        d: d,
        c_inverse_order: cwitness,
    };
    witnesscd
}

use algebra::biginteger::BigInteger256 as BigInteger;
use algebra::tweedle::{FpParameters, FqParameters};

impl DetSquareRootParameters for FpParameters {
    const TWO_TO_TWO_ADICITY_INV: Self::BigInt =
        BigInteger([0x3b3a6633d1897d83, 0xc93d5b, 0xf000000000000000, 0xe34ab16]);
}

impl DetSquareRootParameters for FqParameters {
    const TWO_TO_TWO_ADICITY_INV: Self::BigInt =
        BigInteger([0x9b71de17e6d2d5a0, 0x296ee0, 0x8c00000000000000, 0x2ecc05e]);
}
