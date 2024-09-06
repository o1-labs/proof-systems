//! This module contains a list of property tests for the `MVPoly` trait.
//!
//! Any type that implements the `MVPoly` trait should pass these tests.
//!
//! For instance, one can call the `test_mul_by_one` as follows:
//!
//! ```rust
//! use mvpoly::MVPoly;
//! use mvpoly::prime::Dense;
//! use mina_curves::pasta::Fp;
//!
//! #[test]
//! fn test_mul_by_one() {
//!     mvpoly::pbt::test_mul_by_one::<Fp, 2, 2, Dense<Fp, 2, 2>>();
//!     mvpoly::pbt::test_mul_by_one::<Fp, 4, 2, Dense<Fp, 4, 2>>();
//! }
//! ```

use ark_ff::PrimeField;

use crate::MVPoly;

pub fn test_mul_by_one<F: PrimeField, const N: usize, const D: usize, T: MVPoly<F, N, D>>() {
    let mut rng = o1_utils::tests::make_test_rng(None);
    let p1 = unsafe { T::random(&mut rng, None) };
    let one = T::one();
    let p2 = p1.clone() * one.clone();
    assert_eq!(p1.clone(), p2);
    let p3 = one * p1.clone();
    assert_eq!(p1.clone(), p3);
}
