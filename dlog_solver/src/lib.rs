extern crate num_integer;

use num_integer::Integer;

use algebra::{
    One, Field, FftField, Fp256Parameters,
    fields::{FftParameters, Fp256},
};



// Given 
// - an order p field F with p - 1 = t * 2^k, t odd, g an element of order 2^k in F,
// - h : F
// output (c, d) such that
// h = c * g^d, where c is in the orthogonal complement of < g >
fn decompose<P: FftParameters + Fp256Parameters>(h : Fp256<P>) -> (Fp256<P>, u64) {
    let d = two_adic_discrete_log(h);
    let g : Fp256<P> = FftField::two_adic_root_of_unity();
    let c = g.pow([d as u64]).inverse().unwrap() * &h;

    (c,d)
}

// Given 
// - an order p field F with p - 1 = t * 2^e, t odd, g an element of order 2^e in F,
// - h in < g >
// output x such that
// h = g^x
// 
// This uses [this algorithm](https://en.wikipedia.org/wiki/Pohlig%E2%80%93Hellman_algorithm)
fn two_adic_discrete_log<P: FftParameters + Fp256Parameters>(h : Fp256<P>) -> u64 {
    let e = P::TWO_ADICITY as usize;
    let mut x : u64 = 0;
    assert!(e <= 64);
    let g : Fp256<P> = FftField::two_adic_root_of_unity();
    let g_inv = g.inverse().unwrap();

    {
        let gamma = pow2_pow(g, e - 1); // This should just be -1
        assert_eq!(gamma, -Fp256::<P>::one());
    }

    // Invariant: this is equal to g_inv^x at every iteration
    let mut g_inv_to_x = Fp256::<P>::one();
    // Invariant: this is equal to g_inv^{2^k} at iteration k
    let mut g_inv_to_two_to_k = g_inv;
    for k in 0..e {
        let h_k = pow2_pow(g_inv_to_x * h, e - 1 - k); // This should equal +/- 1
        if !h_k.is_one() {
            x |= 1 << k;
            g_inv_to_x *= g_inv_to_two_to_k;
            g_inv_to_two_to_k.square_in_place();
        }
    }

    x
}

// Compute x^{2^k}
fn pow2_pow<F : Field>(x : F, k : usize) -> F {
    let mut res = x;
    for _ in 0..k {
        res.square_in_place();
    }
    res
}




// Given a, b, output GCD of a,b
pub fn egcd<T: Copy + Integer>(a: T, b: T) -> (T, T, T) {
    if a == T::zero() {
        (b, T::zero(), T::one())
    }
    else {
        let (g, x, y) = egcd(b % a, a);
        (g, y - (b / a) * x, x)
    }
}

// given a, m, compute inverse of a mod m
pub fn modinverse<T: Copy + Integer>(a: T, m: T) -> Option<T> {
    let (g, x, _) = egcd(a, m);
    if g != T::one() {
        None
    }
    else {
        Some((x % m + m) % m)
    }
}


// given c of order 2^k, generate a witness to check its order. 
//The witness is cwitness = c^{(2^k)^-1 mod t}. This can be verified by checking
// k squarings of cwitness
fn witness_c_order<P: FftParameters + Fp256Parameters>(c : Fp256<P>, k : u32) -> Fp256<P>{
    let base : u128 = 2;
    let two_to_k = base.pow(k);
    let p = algebra::FpParameters::MODULUS;
    let exp = modinverse(two_to_k, (p-1)/two_to_k);
    let cwitness = c.pow(exp);
    c
}


// convert d to binary
fn witness_d_binary(d: u64) -> algebra::String {
    let bin = format!("{:b}", d);
    bin
}


// renaming the original sqrt function to detsqrt
pub fn det_qrt<P: FftParameters + Fp256Parameters>(a : Fp256<P>) ->Fp256<P>{
    let root = a.sqrt();
    root
}

pub struct Witness_correct_sqrt<P: FftParameters + Fp256Parameters>{
    c: Fp256<P>,
    d: u64,
    c_inverse_order: Fp256<P>,
    d_in_binary : algebra::String;

}


pub fn witness_det_sqrt<P: FftParameters + Fp256Parameters>(b : Fp256<P>)->  Witness_correct_sqrt<P>{
    let (c,d) : (Fp256<P>, u64) = decompose(b);
    let cwitness : Fp256<P> = witness_c_order(c,P::TWO_ADICITY);
    let dwitness : algebra::String = witness_d_binary(d);
    let witnesscd: Witness_correct_sqrt<P> = Witness_correct_sqrt<P> { c: c, d: d, c_inverse_order : cwitness, d_in_binary : dwitness};

}