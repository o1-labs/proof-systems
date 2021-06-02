/*
TODO(mimoo): find a way to get access to algebra::tests
use algebra_core::{test_rng, AffineCurve};
use rand::Rng;

use crate::pasta::*;

use algebra::tests::{curves::*, groups::*};

#[test]
fn test_pallas_projective_curve() {
    curve_tests::<pallas::Projective>();

    sw_tests::<pallas::PallasParameters>();
}

#[test]
fn test_pallas_projective_group() {
    let mut rng = test_rng();
    let a: pallas::Projective = rng.gen();
    let b: pallas::Projective = rng.gen();
    group_test(a, b);
}

#[test]
fn test_pallas_generator() {
    let generator = pallas::Affine::prime_subgroup_generator();
    assert!(generator.is_on_curve());
    assert!(generator.is_in_correct_subgroup_assuming_on_curve());
}
*/
