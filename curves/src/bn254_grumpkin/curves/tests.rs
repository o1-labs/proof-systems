use crate::bn254_grumpkin::curves::bn254::{BN254Parameters, ProjectiveBN254, BN254};
use crate::bn254_grumpkin::curves::grumpkin::{Grumpkin, GrumpkinParameters, ProjectiveGrumpkin};
use ark_algebra_test_templates::{curves::*, groups::*};
use ark_ec::AffineCurve;
use ark_std::test_rng;
use rand::Rng;

#[test]
fn test_grumpkin_projective_curve() {
    curve_tests::<ProjectiveGrumpkin>();

    sw_tests::<GrumpkinParameters>();
}

#[test]
fn test_bn254_projective_curve() {
    curve_tests::<ProjectiveBN254>();

    sw_tests::<BN254Parameters>();
}

#[test]
fn test_grumpkin_projective_group() {
    let mut rng = test_rng();
    let a: ProjectiveGrumpkin = rng.gen();
    let b: ProjectiveGrumpkin = rng.gen();
    group_test(a, b);
}

#[test]
fn test_grumpkin_generator() {
    let generator = Grumpkin::prime_subgroup_generator();
    assert!(generator.is_on_curve());
    assert!(generator.is_in_correct_subgroup_assuming_on_curve());
}

#[test]
fn test_bn254_projective_group() {
    let mut rng = test_rng();
    let a: ProjectiveBN254 = rng.gen();
    let b: ProjectiveBN254 = rng.gen();
    group_test(a, b);
}

#[test]
fn test_bn254_generator() {
    let generator = BN254::prime_subgroup_generator();
    assert!(generator.is_on_curve());
    assert!(generator.is_in_correct_subgroup_assuming_on_curve());
}
