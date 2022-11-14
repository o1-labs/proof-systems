use ark_algebra_test_templates::{curves::*, groups::*};
use ark_ec::AffineCurve;
use ark_std::test_rng;
use rand::Rng;

use super::pallas;

#[test]
fn test_pallas_projective_curve() {
    curve_tests::<pallas::ProjectivePallas>();

    sw_tests::<pallas::PallasParameters>();
}

#[test]
fn test_pallas_projective_group() {
    let mut rng = test_rng();
    let a: pallas::ProjectivePallas = rng.gen();
    let b: pallas::ProjectivePallas = rng.gen();
    group_test(a, b);
}

#[test]
fn test_pallas_generator() {
    let generator = pallas::Pallas::prime_subgroup_generator();
    assert!(generator.is_on_curve());
    assert!(generator.is_in_correct_subgroup_assuming_on_curve());
}
