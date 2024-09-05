use ark_ff::{Field, One, UniformRand, Zero};
use mina_curves::pasta::Fp;
use mvpoly::{monomials::Sparse, MVPoly};
use rand::{seq::SliceRandom, Rng};

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

#[test]
fn test_homogeneous_eval() {
    let mut rng = o1_utils::tests::make_test_rng(None);
    let random_eval = std::array::from_fn(|_| Fp::rand(&mut rng));
    let u = Fp::rand(&mut rng);
    // Homogeneous form is u^2
    let p1 = Sparse::<Fp, 4, 2>::one();
    let homogenous_eval = p1.homogeneous_eval(&random_eval, u);
    assert_eq!(homogenous_eval, u * u);

    let mut p2 = Sparse::<Fp, 4, 2>::zero();
    // X1
    p2.add_monomial([1, 0, 0, 0], Fp::one());
    let homogenous_eval = p2.homogeneous_eval(&random_eval, u);
    assert_eq!(homogenous_eval, random_eval[0] * u);

    let mut p3 = Sparse::<Fp, 4, 2>::zero();
    // X2
    p3.add_monomial([0, 1, 0, 0], Fp::one());
    let homogenous_eval = p3.homogeneous_eval(&random_eval, u);
    assert_eq!(homogenous_eval, random_eval[1] * u);

    let mut p4 = Sparse::<Fp, 4, 2>::zero();
    // X1 * X2
    p4.add_monomial([1, 1, 0, 0], Fp::one());
    let homogenous_eval = p4.homogeneous_eval(&random_eval, u);
    assert_eq!(homogenous_eval, random_eval[0] * random_eval[1]);

    let mut p5 = Sparse::<Fp, 4, 2>::zero();
    // X1^2
    p5.add_monomial([2, 0, 0, 0], Fp::one());
    let homogenous_eval = p5.homogeneous_eval(&random_eval, u);
    assert_eq!(homogenous_eval, random_eval[0] * random_eval[0]);

    let mut p6 = Sparse::<Fp, 4, 2>::zero();
    // X2^2 + X1^2
    p6.add_monomial([0, 2, 0, 0], Fp::one());
    p6.add_monomial([2, 0, 0, 0], Fp::one());
    let homogenous_eval = p6.homogeneous_eval(&random_eval, u);
    assert_eq!(
        homogenous_eval,
        random_eval[1] * random_eval[1] + random_eval[0] * random_eval[0]
    );

    let mut p7 = Sparse::<Fp, 4, 2>::zero();
    // X2^2 + X1^2 + X1 + 42
    p7.add_monomial([0, 2, 0, 0], Fp::one());
    p7.add_monomial([2, 0, 0, 0], Fp::one());
    p7.add_monomial([1, 0, 0, 0], Fp::one());
    p7.add_monomial([0, 0, 0, 0], Fp::from(42));
    let homogenous_eval = p7.homogeneous_eval(&random_eval, u);
    assert_eq!(
        homogenous_eval,
        random_eval[1] * random_eval[1]
            + random_eval[0] * random_eval[0]
            + u * random_eval[0]
            + u * u * Fp::from(42)
    );
}

#[test]
fn test_add_monomial() {
    let mut rng = o1_utils::tests::make_test_rng(None);

    // Adding constant monomial one to zero
    let mut p1 = Sparse::<Fp, 4, 2>::zero();
    p1.add_monomial([0, 0, 0, 0], Fp::one());
    assert_eq!(p1, Sparse::<Fp, 4, 2>::one());

    // Adding random constant monomial one to zero
    let mut p2 = Sparse::<Fp, 4, 2>::zero();
    let random_c = Fp::rand(&mut rng);
    p2.add_monomial([0, 0, 0, 0], random_c);
    assert_eq!(p2, Sparse::<Fp, 4, 2>::from(random_c));

    let mut p3 = Sparse::<Fp, 4, 2>::zero();
    let random_c1 = Fp::rand(&mut rng);
    let random_c2 = Fp::rand(&mut rng);
    // X1 + X2
    p3.add_monomial([1, 0, 0, 0], random_c1);
    p3.add_monomial([0, 1, 0, 0], random_c2);
    let random_eval = std::array::from_fn(|_| Fp::rand(&mut rng));
    let eval_p3 = p3.eval(&random_eval);
    let exp_eval_p3 = random_c1 * random_eval[0] + random_c2 * random_eval[1];
    assert_eq!(eval_p3, exp_eval_p3);

    let mut p4 = Sparse::<Fp, 4, 2>::zero();
    let random_c1 = Fp::rand(&mut rng);
    let random_c2 = Fp::rand(&mut rng);
    // X1^2 + X2^2
    p4.add_monomial([2, 0, 0, 0], random_c1);
    p4.add_monomial([0, 2, 0, 0], random_c2);
    let random_eval = std::array::from_fn(|_| Fp::rand(&mut rng));
    let eval_p4 = p4.eval(&random_eval);
    let exp_eval_p4 =
        random_c1 * random_eval[0] * random_eval[0] + random_c2 * random_eval[1] * random_eval[1];
    assert_eq!(eval_p4, exp_eval_p4);
}

#[test]
fn test_mvpoly_compute_cross_terms_degree_two_unit_test() {
    let mut rng = o1_utils::tests::make_test_rng(None);

    {
        // Homogeneous form is Y^2
        let p1 = Sparse::<Fp, 4, 2>::from(Fp::from(1));

        let random_eval1: [Fp; 4] = std::array::from_fn(|_| Fp::rand(&mut rng));
        let random_eval2: [Fp; 4] = std::array::from_fn(|_| Fp::rand(&mut rng));
        let u1 = Fp::rand(&mut rng);
        let u2 = Fp::rand(&mut rng);
        let cross_terms = p1.compute_cross_terms(&random_eval1, &random_eval2, u1, u2);

        // We only have one cross-term in this case as degree 2
        assert_eq!(cross_terms.len(), 1);
        // Cross term of constant is r * (2 u1 u2)
        assert_eq!(cross_terms[&1], (u1 * u2).double());
    }
}

#[test]
fn test_mvpoly_compute_cross_terms_degree_two() {
    let mut rng = o1_utils::tests::make_test_rng(None);
    let p1 = unsafe { Sparse::<Fp, 4, 2>::random(&mut rng, None) };
    let random_eval1: [Fp; 4] = std::array::from_fn(|_| Fp::rand(&mut rng));
    let random_eval2: [Fp; 4] = std::array::from_fn(|_| Fp::rand(&mut rng));
    let u1 = Fp::rand(&mut rng);
    let u2 = Fp::rand(&mut rng);
    let cross_terms = p1.compute_cross_terms(&random_eval1, &random_eval2, u1, u2);
    // We only have one cross-term in this case
    assert_eq!(cross_terms.len(), 1);

    let r = Fp::rand(&mut rng);
    let random_lincomb: [Fp; 4] = std::array::from_fn(|i| random_eval1[i] + r * random_eval2[i]);

    let lhs = p1.homogeneous_eval(&random_lincomb, u1 + r * u2);

    let rhs = {
        let eval1_hom = p1.homogeneous_eval(&random_eval1, u1);
        let eval2_hom = p1.homogeneous_eval(&random_eval2, u2);
        let cross_terms_eval = cross_terms.iter().fold(Fp::zero(), |acc, (power, term)| {
            acc + r.pow([*power as u64]) * term
        });
        eval1_hom + r * r * eval2_hom + cross_terms_eval
    };
    assert_eq!(lhs, rhs);
}

#[test]
fn test_mvpoly_compute_cross_terms_degree_three() {
    let mut rng = o1_utils::tests::make_test_rng(None);
    let p1 = unsafe { Sparse::<Fp, 4, 3>::random(&mut rng, None) };
    let random_eval1: [Fp; 4] = std::array::from_fn(|_| Fp::rand(&mut rng));
    let random_eval2: [Fp; 4] = std::array::from_fn(|_| Fp::rand(&mut rng));
    let u1 = Fp::rand(&mut rng);
    let u2 = Fp::rand(&mut rng);
    let cross_terms = p1.compute_cross_terms(&random_eval1, &random_eval2, u1, u2);

    assert_eq!(cross_terms.len(), 2);

    let r = Fp::rand(&mut rng);
    let random_lincomb: [Fp; 4] = std::array::from_fn(|i| random_eval1[i] + r * random_eval2[i]);

    let lhs = p1.homogeneous_eval(&random_lincomb, u1 + r * u2);

    let rhs = {
        let eval1_hom = p1.homogeneous_eval(&random_eval1, u1);
        let eval2_hom = p1.homogeneous_eval(&random_eval2, u2);
        let cross_terms_eval = cross_terms.iter().fold(Fp::zero(), |acc, (power, term)| {
            acc + r.pow([*power as u64]) * term
        });
        let r_cube = r.pow([3]);
        eval1_hom + r_cube * eval2_hom + cross_terms_eval
    };
    assert_eq!(lhs, rhs);
}

#[test]
fn test_mvpoly_compute_cross_terms_degree_four() {
    let mut rng = o1_utils::tests::make_test_rng(None);
    let p1 = unsafe { Sparse::<Fp, 6, 4>::random(&mut rng, None) };
    let random_eval1: [Fp; 6] = std::array::from_fn(|_| Fp::rand(&mut rng));
    let random_eval2: [Fp; 6] = std::array::from_fn(|_| Fp::rand(&mut rng));
    let u1 = Fp::rand(&mut rng);
    let u2 = Fp::rand(&mut rng);
    let cross_terms = p1.compute_cross_terms(&random_eval1, &random_eval2, u1, u2);

    assert_eq!(cross_terms.len(), 3);

    let r = Fp::rand(&mut rng);
    let random_lincomb: [Fp; 6] = std::array::from_fn(|i| random_eval1[i] + r * random_eval2[i]);

    let lhs = p1.homogeneous_eval(&random_lincomb, u1 + r * u2);

    let rhs = {
        let eval1_hom = p1.homogeneous_eval(&random_eval1, u1);
        let eval2_hom = p1.homogeneous_eval(&random_eval2, u2);
        let cross_terms_eval = cross_terms.iter().fold(Fp::zero(), |acc, (power, term)| {
            acc + r.pow([*power as u64]) * term
        });
        let r_four = r.pow([4]);
        eval1_hom + r_four * eval2_hom + cross_terms_eval
    };
    assert_eq!(lhs, rhs);
}

#[test]
fn test_mvpoly_compute_cross_terms_degree_five() {
    let mut rng = o1_utils::tests::make_test_rng(None);
    let p1 = unsafe { Sparse::<Fp, 3, 5>::random(&mut rng, None) };
    let random_eval1: [Fp; 3] = std::array::from_fn(|_| Fp::rand(&mut rng));
    let random_eval2: [Fp; 3] = std::array::from_fn(|_| Fp::rand(&mut rng));
    let u1 = Fp::rand(&mut rng);
    let u2 = Fp::rand(&mut rng);
    let cross_terms = p1.compute_cross_terms(&random_eval1, &random_eval2, u1, u2);

    assert_eq!(cross_terms.len(), 4);

    let r = Fp::rand(&mut rng);
    let random_lincomb: [Fp; 3] = std::array::from_fn(|i| random_eval1[i] + r * random_eval2[i]);

    let lhs = p1.homogeneous_eval(&random_lincomb, u1 + r * u2);

    let rhs = {
        let eval1_hom = p1.homogeneous_eval(&random_eval1, u1);
        let eval2_hom = p1.homogeneous_eval(&random_eval2, u2);
        let cross_terms_eval = cross_terms.iter().fold(Fp::zero(), |acc, (power, term)| {
            acc + r.pow([*power as u64]) * term
        });
        let r_five = r.pow([5]);
        eval1_hom + r_five * eval2_hom + cross_terms_eval
    };
    assert_eq!(lhs, rhs);
}

#[test]
fn test_mvpoly_compute_cross_terms_degree_six() {
    let mut rng = o1_utils::tests::make_test_rng(None);
    let p1 = unsafe { Sparse::<Fp, 4, 6>::random(&mut rng, None) };
    let random_eval1: [Fp; 4] = std::array::from_fn(|_| Fp::rand(&mut rng));
    let random_eval2: [Fp; 4] = std::array::from_fn(|_| Fp::rand(&mut rng));
    let u1 = Fp::rand(&mut rng);
    let u2 = Fp::rand(&mut rng);
    let cross_terms = p1.compute_cross_terms(&random_eval1, &random_eval2, u1, u2);

    assert_eq!(cross_terms.len(), 5);

    let r = Fp::rand(&mut rng);
    let random_lincomb: [Fp; 4] = std::array::from_fn(|i| random_eval1[i] + r * random_eval2[i]);

    let lhs = p1.homogeneous_eval(&random_lincomb, u1 + r * u2);

    let rhs = {
        let eval1_hom = p1.homogeneous_eval(&random_eval1, u1);
        let eval2_hom = p1.homogeneous_eval(&random_eval2, u2);
        let cross_terms_eval = cross_terms.iter().fold(Fp::zero(), |acc, (power, term)| {
            acc + r.pow([*power as u64]) * term
        });
        let r_six = r.pow([6]);
        eval1_hom + r_six * eval2_hom + cross_terms_eval
    };
    assert_eq!(lhs, rhs);
}

#[test]
fn test_mvpoly_compute_cross_terms_degree_seven() {
    let mut rng = o1_utils::tests::make_test_rng(None);
    let p1 = unsafe { Sparse::<Fp, 4, 7>::random(&mut rng, None) };
    let random_eval1: [Fp; 4] = std::array::from_fn(|_| Fp::rand(&mut rng));
    let random_eval2: [Fp; 4] = std::array::from_fn(|_| Fp::rand(&mut rng));
    let u1 = Fp::rand(&mut rng);
    let u2 = Fp::rand(&mut rng);
    let cross_terms = p1.compute_cross_terms(&random_eval1, &random_eval2, u1, u2);

    assert_eq!(cross_terms.len(), 6);

    let r = Fp::rand(&mut rng);
    let random_lincomb: [Fp; 4] = std::array::from_fn(|i| random_eval1[i] + r * random_eval2[i]);

    let lhs = p1.homogeneous_eval(&random_lincomb, u1 + r * u2);

    let rhs = {
        let eval1_hom = p1.homogeneous_eval(&random_eval1, u1);
        let eval2_hom = p1.homogeneous_eval(&random_eval2, u2);
        let cross_terms_eval = cross_terms.iter().fold(Fp::zero(), |acc, (power, term)| {
            acc + r.pow([*power as u64]) * term
        });
        let r_seven = r.pow([7]);
        eval1_hom + r_seven * eval2_hom + cross_terms_eval
    };
    assert_eq!(lhs, rhs);
}

#[test]
fn test_is_multilinear() {
    let mut rng = o1_utils::tests::make_test_rng(None);
    let p1 = Sparse::<Fp, 6, 2>::zero();
    assert!(p1.is_multilinear());

    let c = Fp::rand(&mut rng);
    let p2 = Sparse::<Fp, 6, 2>::from(c);
    assert!(p2.is_multilinear());

    {
        let mut p = Sparse::<Fp, 6, 3>::zero();
        let c = Fp::rand(&mut rng);
        let idx = rng.gen_range(0..6);
        let monomials_exponents = std::array::from_fn(|i| if i == idx { 1 } else { 0 });
        p.add_monomial(monomials_exponents, c);
        assert!(p.is_multilinear());
    }

    {
        let mut p = Sparse::<Fp, 6, 4>::zero();
        let c = Fp::rand(&mut rng);
        let nb_var = rng.gen_range(0..4);
        let mut monomials_exponents: [usize; 6] =
            std::array::from_fn(|i| if i <= nb_var { 1 } else { 0 });
        monomials_exponents.shuffle(&mut rng);
        p.add_monomial(monomials_exponents, c);
        assert!(p.is_multilinear());
    }

    // Very unlikely to have a random polynomial being multilinear
    let p3 = unsafe { Sparse::<Fp, 6, 4>::random(&mut rng, None) };
    assert!(!p3.is_multilinear());
}
