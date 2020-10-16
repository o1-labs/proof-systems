/*****************************************************************************************************************

This source file tests polynomial commitments, batched openings and
verification of a batch of batched opening proofs of polynomial commitments

*****************************************************************************************************************/

use rand::Rng;
use rand_core::OsRng;

use algebra::{
    fields::{FftParameters, Fp256},
    tweedle::{FpParameters, FqParameters},
    FftField, Field, Fp256Parameters, One, SquareRootField, UniformRand,
};
use dlog_solver::{
    compose, decompose, in_orthogonal_complement, two_adic_discrete_log, DetSquareRootField,
    DetSquareRootParameters,
};

#[test]
fn dlog_solve() {
    fn f<P: FftParameters + Fp256Parameters + DetSquareRootParameters>() {
        let rng = &mut OsRng;

        let e = P::TWO_ADICITY as usize;
        let g: Fp256<P> = FftField::two_adic_root_of_unity();
        let r: u64 = rng.gen_range(0, 1 << e);

        let d = two_adic_discrete_log(g.pow([r]));
        assert_eq!(d, r);
    }

    f::<FpParameters>();
    f::<FqParameters>()
}

#[test]
fn dlog_full() {
    fn f<P: FftParameters + Fp256Parameters + DetSquareRootParameters>() {
        let rng = &mut OsRng;

        let x = Fp256::<P>::rand(rng);
        let (c, d) = decompose(&x);
        assert!(in_orthogonal_complement(c));
        assert_eq!(compose((c, d)), x);
    }

    f::<FpParameters>();
    f::<FqParameters>();
}

#[test]
fn det_sqrt() {
    fn f<P: FftParameters + Fp256Parameters + DetSquareRootParameters>() {
        let rng = &mut OsRng;

        let x = Fp256::<P>::rand(rng).square();

        let y = x.det_sqrt().unwrap();

        let (_, d) = decompose(&y);
        assert_eq!(d >> (P::TWO_ADICITY - 1), 0);

        assert_eq!(y * y, x);
    }

    for _ in 0..10 {
        f::<FpParameters>();
        f::<FqParameters>();
    }
}
