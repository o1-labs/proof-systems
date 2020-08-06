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

