use ark_ff::{One, UniformRand, Zero};
use mina_curves::pasta::Fp;
use mvpoly::{prime::Dense, utils::PrimeNumberGenerator};

#[test]
fn test_vector_space_dimension() {
    assert_eq!(Dense::<Fp, 2, 2>::dimension(), 6);
    assert_eq!(Dense::<Fp, 3, 2>::dimension(), 10);
    assert_eq!(Dense::<Fp, 1, 10>::dimension(), 11);
}

#[test]
fn test_add() {
    let p1 = Dense::<Fp, 2, 2>::new();
    let p2 = Dense::<Fp, 2, 2>::new();
    let _p3 = p1 + p2;
}

#[test]
pub fn test_normalized_indices() {
    let indices = Dense::<Fp, 2, 2>::compute_normalized_indices();
    assert_eq!(indices.len(), 6);
    assert_eq!(indices[0], 1);
    assert_eq!(indices[1], 2);
    assert_eq!(indices[2], 3);
    assert_eq!(indices[3], 4);
    assert_eq!(indices[4], 6);
    assert_eq!(indices[5], 9);

    let indices = Dense::<Fp, 3, 2>::compute_normalized_indices();
    assert_eq!(indices.len(), 10);
    assert_eq!(indices[0], 1);
    assert_eq!(indices[1], 2);
    assert_eq!(indices[2], 3);
    assert_eq!(indices[3], 4);
    assert_eq!(indices[4], 5);
    assert_eq!(indices[5], 6);
    assert_eq!(indices[6], 9);
    assert_eq!(indices[7], 10);
    assert_eq!(indices[8], 15);
    assert_eq!(indices[9], 25);
}

#[test]
fn test_is_homogeneous() {
    // X1 X2 + X1^2 + X1^2
    let coeffs: Vec<Fp> = vec![
        Fp::zero(),
        Fp::zero(),
        Fp::zero(),
        Fp::one(),
        Fp::one(),
        Fp::one(),
    ];
    let p = Dense::<Fp, 2, 2>::from_coeffs(coeffs);
    assert!(p.is_homogeneous());

    // X1 X2 + X1^2
    let coeffs: Vec<Fp> = vec![
        Fp::zero(),
        Fp::zero(),
        Fp::zero(),
        Fp::one(),
        Fp::one(),
        Fp::zero(),
    ];
    let p = Dense::<Fp, 2, 2>::from_coeffs(coeffs);
    assert!(p.is_homogeneous());

    // X1 X2 + X2^2
    let coeffs: Vec<Fp> = vec![
        Fp::zero(),
        Fp::zero(),
        Fp::zero(),
        Fp::one(),
        Fp::zero(),
        Fp::one(),
    ];
    let p = Dense::<Fp, 2, 2>::from_coeffs(coeffs);
    assert!(p.is_homogeneous());

    // X1 X2
    let coeffs: Vec<Fp> = vec![
        Fp::zero(),
        Fp::zero(),
        Fp::zero(),
        Fp::one(),
        Fp::zero(),
        Fp::zero(),
    ];
    let p = Dense::<Fp, 2, 2>::from_coeffs(coeffs);
    assert!(p.is_homogeneous());
}

#[test]
fn test_is_not_homogeneous() {
    // 1 + X1 X2 + X1^2 + X2^2
    let coeffs: Vec<Fp> = vec![
        Fp::from(42_u32),
        Fp::zero(),
        Fp::zero(),
        Fp::one(),
        Fp::one(),
        Fp::one(),
    ];
    let p = Dense::<Fp, 2, 2>::from_coeffs(coeffs);
    assert!(!p.is_homogeneous());

    let coeffs: Vec<Fp> = vec![
        Fp::zero(),
        Fp::zero(),
        Fp::one(),
        Fp::one(),
        Fp::one(),
        Fp::zero(),
    ];
    let p = Dense::<Fp, 2, 2>::from_coeffs(coeffs);
    assert!(!p.is_homogeneous());
}

#[test]
fn test_mul() {
    let coeff_p1 = vec![
        Fp::zero(),
        Fp::from(2_u32),
        Fp::one(),
        Fp::zero(),
        Fp::zero(),
        Fp::zero(),
    ];
    let coeff_p2 = vec![
        Fp::from(3_u32),
        Fp::zero(),
        Fp::one(),
        Fp::zero(),
        Fp::zero(),
        Fp::zero(),
    ];
    let coeff_p3 = vec![
        Fp::zero(),
        Fp::from(6_u32),
        Fp::from(3_u32),
        Fp::zero(),
        Fp::from(2_u32),
        Fp::one(),
    ];

    let p1 = Dense::<Fp, 2, 2>::from_coeffs(coeff_p1);
    let p2 = Dense::<Fp, 2, 2>::from_coeffs(coeff_p2);
    let exp_p3 = Dense::<Fp, 2, 2>::from_coeffs(coeff_p3);
    let p3 = p1 * p2;
    assert_eq!(p3, exp_p3);
}

#[test]
fn test_mul_by_one() {
    let mut rng = o1_utils::tests::make_test_rng(None);
    let p1 = unsafe { Dense::<Fp, 7, 2>::random(&mut rng) };
    let one = Dense::<Fp, 7, 2>::one();
    let p2 = p1.clone() * one.clone();
    assert_eq!(p1.clone(), p2);
    let p3 = one * p1.clone();
    assert_eq!(p1.clone(), p3);
}

#[test]
fn test_mul_by_zero() {
    let mut rng = o1_utils::tests::make_test_rng(None);
    let p1 = unsafe { Dense::<Fp, 5, 4>::random(&mut rng) };
    let zero = Dense::<Fp, 5, 4>::zero();
    let p2 = p1.clone() * zero.clone();
    assert_eq!(zero, p2);
    let p3 = zero.clone() * p1.clone();
    assert_eq!(zero.clone(), p3);
}

#[test]
fn test_add_zero() {
    let mut rng = o1_utils::tests::make_test_rng(None);
    let p1 = unsafe { Dense::<Fp, 3, 4>::random(&mut rng) };

    let zero = Dense::<Fp, 3, 4>::zero();
    let p2 = p1.clone() + zero.clone();
    assert_eq!(p1.clone(), p2);
    let p3 = zero.clone() + p1.clone();
    assert_eq!(p1.clone(), p3);
}

#[test]
fn test_double_is_add_twice() {
    let mut rng = o1_utils::tests::make_test_rng(None);
    let p1 = unsafe { Dense::<Fp, 3, 4>::random(&mut rng) };
    let p2 = p1.clone() + p1.clone();
    let p3 = p1.clone().double();
    assert_eq!(p2, p3);
}

#[test]
fn test_sub_zero() {
    let mut rng = o1_utils::tests::make_test_rng(None);
    let p1 = unsafe { Dense::<Fp, 3, 4>::random(&mut rng) };
    let zero = Dense::<Fp, 3, 4>::zero();
    let p2 = p1.clone() - zero.clone();
    assert_eq!(p1.clone(), p2);
}

#[test]
fn test_neg() {
    let mut rng = o1_utils::tests::make_test_rng(None);
    let p1 = unsafe { Dense::<Fp, 3, 4>::random(&mut rng) };
    let p2 = -p1.clone();

    // Test that p1 + (-p1) = 0
    let sum = p1.clone() + p2.clone();
    assert_eq!(sum, Dense::<Fp, 3, 4>::zero());

    // Test that -(-p1) = p1
    let p3 = -p2;
    assert_eq!(p1, p3);

    // Test negation of zero
    let zero = Dense::<Fp, 3, 4>::zero();
    let neg_zero = -zero.clone();
    assert_eq!(zero, neg_zero);
}

#[test]
fn test_neg_ref() {
    let mut rng = o1_utils::tests::make_test_rng(None);
    let p1 = unsafe { Dense::<Fp, 3, 4>::random(&mut rng) };
    let p2 = -&p1;

    // Test that p1 + (-&p1) = 0
    let sum = p1.clone() + p2.clone();
    assert_eq!(sum, Dense::<Fp, 3, 4>::zero());

    // Test that -(-&p1) = p1
    let p3 = -&p2;
    assert_eq!(p1, p3);
}

#[test]
fn test_mul_by_scalar() {
    let mut rng = o1_utils::tests::make_test_rng(None);
    let p1 = unsafe { Dense::<Fp, 4, 5>::random(&mut rng) };
    let mut p2 = Dense::<Fp, 4, 5>::zero();
    let c = Fp::rand(&mut rng);
    p2[0] = c;
    assert_eq!(p2 * p1.clone(), p1.clone().mul_by_scalar(c))
}

#[test]
fn test_mul_by_scalar_with_zero() {
    let mut rng = o1_utils::tests::make_test_rng(None);
    let p1 = unsafe { Dense::<Fp, 4, 5>::random(&mut rng) };
    let c = Fp::zero();
    assert_eq!(p1.mul_by_scalar(c), Dense::<Fp, 4, 5>::zero())
}

#[test]
fn test_mul_by_scalar_with_one() {
    let mut rng = o1_utils::tests::make_test_rng(None);
    let p1 = unsafe { Dense::<Fp, 4, 5>::random(&mut rng) };
    let c = Fp::one();
    assert_eq!(p1.mul_by_scalar(c), p1)
}

#[test]
fn test_mul_by_scalar_with_from() {
    let mut rng = o1_utils::tests::make_test_rng(None);
    let p = unsafe { Dense::<Fp, 4, 5>::random(&mut rng) };
    let c = Fp::rand(&mut rng);

    // Create a constant polynomial from the field element
    let constant_poly = Dense::<Fp, 4, 5>::from(c);

    // Multiply p by c using mul_by_scalar
    let result1 = p.mul_by_scalar(c);

    // Multiply p by the constant polynomial
    let result2 = p.clone() * constant_poly;

    // Check that both methods produce the same result
    assert_eq!(result1, result2);
}

#[test]
fn test_from_variable() {
    // Test for y variable (index 2)
    let y = Dense::<Fp, 4, 5>::from_variable(2_usize);
    assert_eq!(y[1], Fp::one());
    assert_eq!(y[0], Fp::zero());
    assert_eq!(y[2], Fp::zero());
    assert_eq!(y[3], Fp::zero());
    assert_eq!(y[4], Fp::zero());
    assert_eq!(y[5], Fp::zero());

    // Test for z variable (index 3)
    let z = Dense::<Fp, 4, 5>::from_variable(3_usize);
    assert_eq!(z[0], Fp::zero());
    assert_eq!(z[1], Fp::zero());
    assert_eq!(z[2], Fp::one());
    assert_eq!(z[3], Fp::zero());
    assert_eq!(z[4], Fp::zero());

    // Test for w variable (index 5)
    let w = Dense::<Fp, 4, 5>::from_variable(5_usize);
    assert_eq!(w[0], Fp::zero());
    assert_eq!(w[1], Fp::zero());
    assert_eq!(w[2], Fp::zero());
    assert_eq!(w[3], Fp::zero());
    assert_eq!(w[4], Fp::one());
}

#[test]
fn test_from_variable_column() {
    // Simulate a real usecase
    enum Column {
        X(usize),
    }

    impl From<Column> for usize {
        fn from(val: Column) -> usize {
            match val {
                Column::X(i) => {
                    let mut prime_gen = PrimeNumberGenerator::new();
                    prime_gen.get_nth_prime(i + 1)
                }
            }
        }
    }

    let p = Dense::<Fp, 4, 5>::from_variable(Column::X(0));
    assert_eq!(p[0], Fp::zero());
    assert_eq!(p[1], Fp::one());
    assert_eq!(p[2], Fp::zero());
    assert_eq!(p[3], Fp::zero());
    assert_eq!(p[4], Fp::zero());
    assert_eq!(p[5], Fp::zero());

    // Test for z variable (index 3)
    let p = Dense::<Fp, 4, 5>::from_variable(Column::X(1));
    assert_eq!(p[0], Fp::zero());
    assert_eq!(p[1], Fp::zero());
    assert_eq!(p[2], Fp::one());
    assert_eq!(p[3], Fp::zero());
    assert_eq!(p[4], Fp::zero());

    // Test for w variable (index 5)
    let p = Dense::<Fp, 4, 5>::from_variable(Column::X(2));
    assert_eq!(p[0], Fp::zero());
    assert_eq!(p[1], Fp::zero());
    assert_eq!(p[2], Fp::zero());
    assert_eq!(p[3], Fp::zero());
    assert_eq!(p[4], Fp::one());
}
