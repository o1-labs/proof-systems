use ark_ff::{One, UniformRand, Zero};
use mina_curves::pasta::Fp;
use mvpoly::{monomials::Sparse, MVPoly};
use rand::Rng;

#[test]
fn test_mul_by_one() {
    let mut rng = o1_utils::tests::make_test_rng(None);
    let p1 = unsafe { Sparse::<Fp, 7, 2>::random(&mut rng, None) };
    let one = Sparse::<Fp, 7, 2>::one();
    let p2 = p1.clone() * one.clone();
    assert_eq!(p1.clone(), p2);
    let p3 = one * p1.clone();
    assert_eq!(p1.clone(), p3);
}

#[test]
fn test_mul_by_zero() {
    let mut rng = o1_utils::tests::make_test_rng(None);
    let p1 = unsafe { Sparse::<Fp, 5, 4>::random(&mut rng, None) };
    let zero = Sparse::<Fp, 5, 4>::zero();
    let p2 = p1.clone() * zero.clone();
    assert_eq!(zero, p2);
    let p3 = zero.clone() * p1.clone();
    assert_eq!(zero.clone(), p3);
}

#[test]
fn test_add_zero() {
    let mut rng = o1_utils::tests::make_test_rng(None);
    let p1 = unsafe { Sparse::<Fp, 3, 4>::random(&mut rng, None) };

    let zero = Sparse::<Fp, 3, 4>::zero();
    let p2 = p1.clone() + zero.clone();
    assert_eq!(p1.clone(), p2);
    let p3 = zero.clone() + p1.clone();
    assert_eq!(p1.clone(), p3);
}

#[test]
fn test_double_is_add_twice() {
    let mut rng = o1_utils::tests::make_test_rng(None);
    let p1 = unsafe { Sparse::<Fp, 3, 4>::random(&mut rng, None) };
    let p2 = p1.clone() + p1.clone();
    let p3 = p1.clone().double();
    assert_eq!(p2, p3);
}

#[test]
fn test_sub_zero() {
    let mut rng = o1_utils::tests::make_test_rng(None);
    let p1 = unsafe { Sparse::<Fp, 3, 4>::random(&mut rng, None) };
    let zero = Sparse::<Fp, 3, 4>::zero();
    let p2 = p1.clone() - zero.clone();
    assert_eq!(p1.clone(), p2);
}

#[test]
fn test_neg() {
    let mut rng = o1_utils::tests::make_test_rng(None);
    let p1 = unsafe { Sparse::<Fp, 3, 4>::random(&mut rng, None) };
    let p2 = -p1.clone();

    // Test that p1 + (-p1) = 0
    let sum = p1.clone() + p2.clone();
    assert_eq!(sum, Sparse::<Fp, 3, 4>::zero());

    // Test that -(-p1) = p1
    let p3 = -p2;
    assert_eq!(p1, p3);

    // Test negation of zero
    let zero = Sparse::<Fp, 3, 4>::zero();
    let neg_zero = -zero.clone();
    assert_eq!(zero, neg_zero);
}

#[test]
fn test_neg_ref() {
    let mut rng = o1_utils::tests::make_test_rng(None);
    let p1 = unsafe { Sparse::<Fp, 3, 4>::random(&mut rng, None) };
    let p2 = -&p1;

    // Test that p1 + (-&p1) = 0
    let sum = p1.clone() + p2.clone();
    assert_eq!(sum, Sparse::<Fp, 3, 4>::zero());

    // Test that -(-&p1) = p1
    let p3 = -&p2;
    assert_eq!(p1, p3);
}

#[test]
fn test_mul_by_scalar() {
    let mut rng = o1_utils::tests::make_test_rng(None);
    let p1 = unsafe { Sparse::<Fp, 4, 5>::random(&mut rng, None) };
    let mut p2 = Sparse::<Fp, 4, 5>::zero();
    let c = Fp::rand(&mut rng);
    p2.modify_monomial([0; 4], c);
    assert_eq!(p2 * p1.clone(), p1.clone().mul_by_scalar(c))
}

#[test]
fn test_mul_by_scalar_with_zero() {
    let mut rng = o1_utils::tests::make_test_rng(None);
    let p1 = unsafe { Sparse::<Fp, 4, 5>::random(&mut rng, None) };
    let c = Fp::zero();
    assert_eq!(p1.mul_by_scalar(c), Sparse::<Fp, 4, 5>::zero())
}

#[test]
fn test_mul_by_scalar_with_one() {
    let mut rng = o1_utils::tests::make_test_rng(None);
    let p1 = unsafe { Sparse::<Fp, 4, 5>::random(&mut rng, None) };
    let c = Fp::one();
    assert_eq!(p1.mul_by_scalar(c), p1)
}

#[test]
fn test_evaluation_zero_polynomial() {
    let mut rng = o1_utils::tests::make_test_rng(None);

    let random_evaluation: [Fp; 4] = std::array::from_fn(|_| Fp::rand(&mut rng));
    let zero = Sparse::<Fp, 4, 5>::zero();
    let evaluation = zero.eval(&random_evaluation);
    assert_eq!(evaluation, Fp::zero());
}

#[test]
fn test_evaluation_constant_polynomial() {
    let mut rng = o1_utils::tests::make_test_rng(None);

    let random_evaluation: [Fp; 4] = std::array::from_fn(|_| Fp::rand(&mut rng));
    let cst = Fp::rand(&mut rng);
    let zero = Sparse::<Fp, 4, 5>::from(cst);
    let evaluation = zero.eval(&random_evaluation);
    assert_eq!(evaluation, cst);
}

#[test]
fn test_eval_pbt_add() {
    let mut rng = o1_utils::tests::make_test_rng(None);

    let random_evaluation: [Fp; 6] = std::array::from_fn(|_| Fp::rand(&mut rng));
    let p1 = unsafe { Sparse::<Fp, 6, 4>::random(&mut rng, None) };
    let p2 = unsafe { Sparse::<Fp, 6, 4>::random(&mut rng, None) };
    let eval_p1 = p1.eval(&random_evaluation);
    let eval_p2 = p2.eval(&random_evaluation);
    {
        let p3 = p1.clone() + p2.clone();
        let eval_p3 = p3.eval(&random_evaluation);
        assert_eq!(eval_p3, eval_p1 + eval_p2);
    }
    // For code coverage, using ref
    {
        let p3 = &p1 + p2.clone();
        let eval_p3 = p3.eval(&random_evaluation);
        assert_eq!(eval_p3, eval_p1 + eval_p2);
    }
    {
        let p3 = &p1 + &p2;
        let eval_p3 = p3.eval(&random_evaluation);
        assert_eq!(eval_p3, eval_p1 + eval_p2);
    }
    {
        let p3 = p1 + &p2;
        let eval_p3 = p3.eval(&random_evaluation);
        assert_eq!(eval_p3, eval_p1 + eval_p2);
    }
}

#[test]
fn test_eval_pbt_sub() {
    let mut rng = o1_utils::tests::make_test_rng(None);

    let random_evaluation: [Fp; 6] = std::array::from_fn(|_| Fp::rand(&mut rng));
    let p1 = unsafe { Sparse::<Fp, 6, 4>::random(&mut rng, None) };
    let p2 = unsafe { Sparse::<Fp, 6, 4>::random(&mut rng, None) };
    let eval_p1 = p1.eval(&random_evaluation);
    let eval_p2 = p2.eval(&random_evaluation);
    {
        let p3 = p1.clone() - p2.clone();
        let eval_p3 = p3.eval(&random_evaluation);
        assert_eq!(eval_p3, eval_p1 - eval_p2);
    }
    {
        let p3 = &p1 - p2.clone();
        let eval_p3 = p3.eval(&random_evaluation);
        assert_eq!(eval_p3, eval_p1 - eval_p2);
    }
    {
        let p3 = p1.clone() - &p2;
        let eval_p3 = p3.eval(&random_evaluation);
        assert_eq!(eval_p3, eval_p1 - eval_p2);
    }
    {
        let p3 = &p1 - &p2;
        let eval_p3 = p3.eval(&random_evaluation);
        assert_eq!(eval_p3, eval_p1 - eval_p2);
    }
}

#[test]
fn test_eval_pbt_mul_by_scalar() {
    let mut rng = o1_utils::tests::make_test_rng(None);

    let random_evaluation: [Fp; 6] = std::array::from_fn(|_| Fp::rand(&mut rng));
    let p1 = unsafe { Sparse::<Fp, 6, 4>::random(&mut rng, None) };
    let c = Fp::rand(&mut rng);
    let p2 = p1.clone() * Sparse::<Fp, 6, 4>::from(c);
    let eval_p1 = p1.eval(&random_evaluation);
    let eval_p2 = p2.eval(&random_evaluation);
    assert_eq!(eval_p2, eval_p1 * c);
}

#[test]
fn test_eval_pbt_neg() {
    let mut rng = o1_utils::tests::make_test_rng(None);

    let random_evaluation: [Fp; 6] = std::array::from_fn(|_| Fp::rand(&mut rng));
    let p1 = unsafe { Sparse::<Fp, 6, 4>::random(&mut rng, None) };
    let p2 = -p1.clone();
    let eval_p1 = p1.eval(&random_evaluation);
    let eval_p2 = p2.eval(&random_evaluation);
    assert_eq!(eval_p2, -eval_p1);
}

#[test]
fn test_degree_constant() {
    let mut rng = o1_utils::tests::make_test_rng(None);
    let c = Fp::rand(&mut rng);
    let p = Sparse::<Fp, 4, 5>::from(c);
    let degree = unsafe { p.degree() };
    assert_eq!(degree, 0);

    let p = Sparse::<Fp, 4, 5>::zero();
    let degree = unsafe { p.degree() };
    assert_eq!(degree, 0);
}

#[test]
fn test_degree_random_degree() {
    let mut rng = o1_utils::tests::make_test_rng(None);
    let max_degree: usize = rng.gen_range(1..5);
    let p: Sparse<Fp, 4, 5> = unsafe { Sparse::random(&mut rng, Some(max_degree)) };
    let degree = unsafe { p.degree() };
    assert!(degree <= max_degree);

    let max_degree: usize = rng.gen_range(1..20);
    // univariate
    let p = unsafe { Sparse::<Fp, 1, 20>::random(&mut rng, Some(max_degree)) };
    let degree = unsafe { p.degree() };
    assert!(degree <= max_degree);
}

#[test]
fn test_is_constant() {
    let mut rng = o1_utils::tests::make_test_rng(None);
    let c = Fp::rand(&mut rng);
    let p = Sparse::<Fp, 4, 5>::from(c);
    assert!(p.is_constant());

    let p = Sparse::<Fp, 4, 5>::zero();
    assert!(p.is_constant());

    // This might be flaky
    let p = unsafe { Sparse::<Fp, 4, 5>::random(&mut rng, None) };
    assert!(!p.is_constant());
}

#[test]
fn test_mvpoly_add_degree_pbt() {
    let mut rng = o1_utils::tests::make_test_rng(None);
    let degree = rng.gen_range(1..5);
    let p1 = unsafe { Sparse::<Fp, 4, 5>::random(&mut rng, Some(degree)) };
    let p2 = unsafe { Sparse::<Fp, 4, 5>::random(&mut rng, Some(degree)) };
    let p3 = p1.clone() + p2.clone();
    let degree_p1 = unsafe { p1.degree() };
    let degree_p2 = unsafe { p2.degree() };
    let degree_p3 = unsafe { p3.degree() };
    assert!(degree_p3 <= std::cmp::max(degree_p1, degree_p2));
}

#[test]
fn test_mvpoly_sub_degree_pbt() {
    let mut rng = o1_utils::tests::make_test_rng(None);
    let degree = rng.gen_range(1..5);
    let p1 = unsafe { Sparse::<Fp, 4, 5>::random(&mut rng, Some(degree)) };
    let p2 = unsafe { Sparse::<Fp, 4, 5>::random(&mut rng, Some(degree)) };
    let p3 = p1.clone() - p2.clone();
    let degree_p1 = unsafe { p1.degree() };
    let degree_p2 = unsafe { p2.degree() };
    let degree_p3 = unsafe { p3.degree() };
    assert!(degree_p3 <= std::cmp::max(degree_p1, degree_p2));
}

#[test]
fn test_mvpoly_neg_degree_pbt() {
    let mut rng = o1_utils::tests::make_test_rng(None);
    let degree = rng.gen_range(1..5);
    let p1 = unsafe { Sparse::<Fp, 4, 5>::random(&mut rng, Some(degree)) };
    let p2 = -p1.clone();
    let degree_p1 = unsafe { p1.degree() };
    let degree_p2 = unsafe { p2.degree() };
    assert_eq!(degree_p1, degree_p2);
}

#[test]
fn test_mvpoly_mul_by_scalar_degree_pbt() {
    let mut rng = o1_utils::tests::make_test_rng(None);
    let degree = rng.gen_range(1..5);
    let p1 = unsafe { Sparse::<Fp, 4, 5>::random(&mut rng, Some(degree)) };
    let c = Fp::rand(&mut rng);
    let p2 = p1.clone() * Sparse::<Fp, 4, 5>::from(c);
    let degree_p1 = unsafe { p1.degree() };
    let degree_p2 = unsafe { p2.degree() };
    assert!(degree_p2 <= degree_p1);
}

#[test]
fn test_mvpoly_mul_degree_pbt() {
    let mut rng = o1_utils::tests::make_test_rng(None);
    // half max degree
    let degree = rng.gen_range(1..3);
    let p1 = unsafe { Sparse::<Fp, 4, 6>::random(&mut rng, Some(degree)) };
    let p2 = unsafe { Sparse::<Fp, 4, 6>::random(&mut rng, Some(degree)) };
    let p3 = p1.clone() * p2.clone();
    let degree_p1 = unsafe { p1.degree() };
    let degree_p2 = unsafe { p2.degree() };
    let degree_p3 = unsafe { p3.degree() };
    assert!(degree_p3 <= degree_p1 + degree_p2);
}

#[test]
fn test_mvpoly_mul_eval_pbt() {
    let mut rng = o1_utils::tests::make_test_rng(None);
    let max_degree = rng.gen_range(1..3);
    let p1 = unsafe { Sparse::<Fp, 4, 6>::random(&mut rng, Some(max_degree)) };
    let p2 = unsafe { Sparse::<Fp, 4, 6>::random(&mut rng, Some(max_degree)) };
    let p3 = p1.clone() * p2.clone();
    let random_evaluation: [Fp; 4] = std::array::from_fn(|_| Fp::rand(&mut rng));
    let eval_p1 = p1.eval(&random_evaluation);
    let eval_p2 = p2.eval(&random_evaluation);
    let eval_p3 = p3.eval(&random_evaluation);
    assert_eq!(eval_p3, eval_p1 * eval_p2);
}

#[test]
fn test_mvpoly_mul_pbt() {
    let mut rng = o1_utils::tests::make_test_rng(None);
    let max_degree = rng.gen_range(1..3);
    let p1 = unsafe { Sparse::<Fp, 4, 6>::random(&mut rng, Some(max_degree)) };
    let p2 = unsafe { Sparse::<Fp, 4, 6>::random(&mut rng, Some(max_degree)) };
    assert_eq!(p1.clone() * p2.clone(), p2.clone() * p1.clone());
}

#[test]
fn test_can_be_printed_with_debug() {
    let mut rng = o1_utils::tests::make_test_rng(None);
    let p1 = unsafe { Sparse::<Fp, 2, 2>::random(&mut rng, None) };
    println!("{:?}", p1);
}

#[test]
fn test_is_zero() {
    let mut rng = o1_utils::tests::make_test_rng(None);
    let p1 = Sparse::<Fp, 4, 6>::zero();
    assert!(p1.is_zero());

    let p2 = unsafe { Sparse::<Fp, 4, 6>::random(&mut rng, None) };
    assert!(!p2.is_zero());
}
