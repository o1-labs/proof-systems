/*
TODO(mimoo): find a way to get access to algebra::tests
use algebra_core::test_rng;
use rand::Rng;

use crate::pasta::*;

use algebra::tests::fields::{field_test, primefield_test, sqrt_field_test};

#[test]
fn test_fp() {
    let mut rng = test_rng();
    let a: Fp = rng.gen();
    let b: Fp = rng.gen();
    field_test(a, b);
    sqrt_field_test(a);
    primefield_test::<Fp>();
}

#[test]
fn test_fq() {
    let mut rng = test_rng();
    let a: Fq = rng.gen();
    let b: Fq = rng.gen();
    field_test(a, b);
    sqrt_field_test(a);
    primefield_test::<Fq>();
}
*/
