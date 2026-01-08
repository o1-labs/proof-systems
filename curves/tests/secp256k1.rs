//! Tests for secp256k1 curve implementation.
//!
//! This module contains:
//! - arkworks standard test templates for field and group operations
//! - Property-based tests (PBT) for algebraic properties
//! - Unit tests for specific known values and regression tests

use ark_algebra_test_templates::*;
use ark_ec::{AdditiveGroup, AffineRepr, CurveGroup, PrimeGroup};
use ark_ff::{Field, PrimeField, UniformRand, Zero};
use core::str::FromStr;
use mina_curves::secp256k1::{Affine, Config, Fq, Fr, Projective, G_GENERATOR_X, G_GENERATOR_Y};
use num_bigint::BigUint;
use proptest::prelude::*;
use rand::SeedableRng;

// ============================================================================
// Arkworks standard test templates
// ============================================================================

test_field!(fq; Fq; mont_prime_field);
test_field!(fr; Fr; mont_prime_field);
test_group!(g1; Projective; sw);

// ============================================================================
// Unit tests for known values
// ============================================================================

#[test]
fn test_generator_is_on_curve() {
    let g = Affine::generator();
    assert!(g.is_on_curve());
    assert!(!g.is_zero());
}

#[test]
fn test_generator_coordinates() {
    // secp256k1 generator point coordinates (in decimal)
    // Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
    // Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
    let expected_gx = BigUint::from_str(
        "55066263022277343669578718895168534326250603453777594175500187360389116729240",
    )
    .unwrap();
    let expected_gy = BigUint::from_str(
        "32670510020758816978083085130507043184471273380659243275938904335757337482424",
    )
    .unwrap();

    let g = Affine::generator();
    let gx_biguint: BigUint = g.x.into();
    let gy_biguint: BigUint = g.y.into();

    assert_eq!(gx_biguint, expected_gx);
    assert_eq!(gy_biguint, expected_gy);
}

#[test]
fn test_generator_constants_match() {
    // Verify that G_GENERATOR_X and G_GENERATOR_Y constants match the generator point
    let g = Affine::generator();
    assert_eq!(g.x, G_GENERATOR_X);
    assert_eq!(g.y, G_GENERATOR_Y);

    // Verify we can construct the generator from constants
    let g_from_constants = Affine::new_unchecked(G_GENERATOR_X, G_GENERATOR_Y);
    assert_eq!(g, g_from_constants);
}

#[test]
fn test_base_field_modulus() {
    // p = 2^256 - 2^32 - 977
    // p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    let expected_p = BigUint::from_str(
        "115792089237316195423570985008687907853269984665640564039457584007908834671663",
    )
    .unwrap();

    let modulus: BigUint = Fq::MODULUS.into();
    assert_eq!(modulus, expected_p);
}

#[test]
fn test_scalar_field_order() {
    // n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    let expected_n = BigUint::from_str(
        "115792089237316195423570985008687907852837564279074904382605163141518161494337",
    )
    .unwrap();

    let order: BigUint = Fr::MODULUS.into();
    assert_eq!(order, expected_n);
}

#[test]
fn test_curve_equation_b_equals_7() {
    // secp256k1: y^2 = x^3 + 7, so COEFF_B = 7
    use ark_ec::short_weierstrass::SWCurveConfig;
    let b = <Config as SWCurveConfig>::COEFF_B;
    assert_eq!(b, Fq::from(7u64));
}

#[test]
fn test_curve_equation_a_equals_0() {
    // secp256k1: y^2 = x^3 + 7, so COEFF_A = 0
    use ark_ec::short_weierstrass::SWCurveConfig;
    let a = <Config as SWCurveConfig>::COEFF_A;
    assert_eq!(a, Fq::from(0u64));
}

#[test]
fn test_cofactor_is_one() {
    use ark_ec::CurveConfig;
    assert_eq!(<Config as CurveConfig>::COFACTOR, &[1u64]);
}

#[test]
fn test_identity_element() {
    let identity = Projective::zero();
    assert!(identity.is_zero());

    let g = Projective::generator();
    assert_eq!(g + identity, g);
    assert_eq!(identity + g, g);
}

#[test]
fn test_scalar_multiplication_by_order() {
    // g * n = identity (where n is the curve order)
    let g = Projective::generator();
    let order = Fr::MODULUS;
    let result = g.mul_bigint(order);
    assert!(result.is_zero());
}

#[test]
fn test_doubling() {
    let g = Projective::generator();
    let double_g = g.double();
    let add_g_g = g + g;
    assert_eq!(double_g, add_g_g);
}

#[test]
fn test_negation() {
    let g = Projective::generator();
    let neg_g = -g;
    let sum = g + neg_g;
    assert!(sum.is_zero());
}

#[test]
fn test_affine_projective_conversion() {
    let g_affine = Affine::generator();
    let g_projective: Projective = g_affine.into();
    let g_back: Affine = g_projective.into_affine();
    assert_eq!(g_affine, g_back);
}

#[test]
fn test_biguint_representation_is_canonical() {
    // Ensure BigUint::into() returns canonical representation, not Montgomery form
    let one = Fq::from(1u64);
    let one_biguint: BigUint = one.into();
    assert_eq!(one_biguint, BigUint::from(1u64));

    let seven = Fq::from(7u64);
    let seven_biguint: BigUint = seven.into();
    assert_eq!(seven_biguint, BigUint::from(7u64));
}

// ============================================================================
// Property-based tests (PBT)
// ============================================================================

fn arb_fq() -> impl Strategy<Value = Fq> {
    any::<[u8; 32]>().prop_map(|bytes| {
        let mut rng = rand::rngs::StdRng::from_seed(bytes);
        Fq::rand(&mut rng)
    })
}

fn arb_fr() -> impl Strategy<Value = Fr> {
    any::<[u8; 32]>().prop_map(|bytes| {
        let mut rng = rand::rngs::StdRng::from_seed(bytes);
        Fr::rand(&mut rng)
    })
}

fn arb_projective() -> impl Strategy<Value = Projective> {
    arb_fr().prop_map(|scalar| Projective::generator() * scalar)
}

proptest! {
    // Field arithmetic properties for Fq

    #[test]
    fn prop_fq_add_commutative(a in arb_fq(), b in arb_fq()) {
        prop_assert_eq!(a + b, b + a);
    }

    #[test]
    fn prop_fq_add_associative(a in arb_fq(), b in arb_fq(), c in arb_fq()) {
        prop_assert_eq!((a + b) + c, a + (b + c));
    }

    #[test]
    fn prop_fq_add_identity(a in arb_fq()) {
        prop_assert_eq!(a + Fq::ZERO, a);
    }

    #[test]
    fn prop_fq_add_inverse(a in arb_fq()) {
        prop_assert_eq!(a + (-a), Fq::ZERO);
    }

    #[test]
    fn prop_fq_mul_commutative(a in arb_fq(), b in arb_fq()) {
        prop_assert_eq!(a * b, b * a);
    }

    #[test]
    fn prop_fq_mul_associative(a in arb_fq(), b in arb_fq(), c in arb_fq()) {
        prop_assert_eq!((a * b) * c, a * (b * c));
    }

    #[test]
    fn prop_fq_mul_identity(a in arb_fq()) {
        prop_assert_eq!(a * Fq::ONE, a);
    }

    #[test]
    fn prop_fq_mul_distributive(a in arb_fq(), b in arb_fq(), c in arb_fq()) {
        prop_assert_eq!(a * (b + c), a * b + a * c);
    }

    #[test]
    fn prop_fq_mul_inverse(a in arb_fq()) {
        if !a.is_zero() {
            let inv = a.inverse().unwrap();
            prop_assert_eq!(a * inv, Fq::ONE);
        }
    }

    #[test]
    fn prop_fq_square_equals_mul(a in arb_fq()) {
        prop_assert_eq!(a.square(), a * a);
    }

    // Field arithmetic properties for Fr

    #[test]
    fn prop_fr_add_commutative(a in arb_fr(), b in arb_fr()) {
        prop_assert_eq!(a + b, b + a);
    }

    #[test]
    fn prop_fr_mul_commutative(a in arb_fr(), b in arb_fr()) {
        prop_assert_eq!(a * b, b * a);
    }

    #[test]
    fn prop_fr_mul_inverse(a in arb_fr()) {
        if !a.is_zero() {
            let inv = a.inverse().unwrap();
            prop_assert_eq!(a * inv, Fr::ONE);
        }
    }

    // Group operation properties

    #[test]
    fn prop_group_add_commutative(a in arb_projective(), b in arb_projective()) {
        prop_assert_eq!(a + b, b + a);
    }

    #[test]
    fn prop_group_add_associative(a in arb_projective(), b in arb_projective(), c in arb_projective()) {
        prop_assert_eq!((a + b) + c, a + (b + c));
    }

    #[test]
    fn prop_group_add_identity(a in arb_projective()) {
        let identity = Projective::zero();
        prop_assert_eq!(a + identity, a);
    }

    #[test]
    fn prop_group_add_inverse(a in arb_projective()) {
        let identity = Projective::zero();
        prop_assert_eq!(a + (-a), identity);
    }

    #[test]
    fn prop_group_double_equals_add(a in arb_projective()) {
        prop_assert_eq!(a.double(), a + a);
    }

    #[test]
    fn prop_scalar_mul_distributive_over_addition(
        p in arb_projective(),
        a in arb_fr(),
        b in arb_fr()
    ) {
        prop_assert_eq!(p * (a + b), p * a + p * b);
    }

    #[test]
    fn prop_scalar_mul_associative(
        p in arb_projective(),
        a in arb_fr(),
        b in arb_fr()
    ) {
        prop_assert_eq!((p * a) * b, p * (a * b));
    }

    #[test]
    fn prop_point_on_curve(p in arb_projective()) {
        let affine: Affine = p.into_affine();
        prop_assert!(affine.is_on_curve() || affine.is_zero());
    }

    #[test]
    fn prop_affine_projective_roundtrip(p in arb_projective()) {
        let affine: Affine = p.into_affine();
        let projective: Projective = affine.into();
        prop_assert_eq!(p, projective);
    }
}
