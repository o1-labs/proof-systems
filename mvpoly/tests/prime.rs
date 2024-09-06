use ark_ff::{One, UniformRand, Zero};
use kimchi::circuits::{
    expr::{ConstantExpr, Expr, ExprInner, Variable},
    gate::CurrOrNext,
};
use mina_curves::pasta::Fp;
use mvpoly::{prime::Dense, utils::PrimeNumberGenerator, MVPoly};
use rand::Rng;

trait RandomPolynomial {
    fn random_dense<const N: usize, const D: usize>(
        rng: &mut impl Rng,
        max_degree: Option<usize>,
    ) -> Dense<Fp, N, D>;
    fn random_evaluation<const N: usize>(rng: &mut impl Rng) -> [Fp; N];
}

impl RandomPolynomial for Fp {
    fn random_dense<const N: usize, const D: usize>(
        rng: &mut impl Rng,
        max_degree: Option<usize>,
    ) -> Dense<Fp, N, D> {
        unsafe { Dense::<Fp, N, D>::random(rng, max_degree) }
    }

    fn random_evaluation<const N: usize>(rng: &mut impl Rng) -> [Fp; N] {
        std::array::from_fn(|_| Fp::rand(rng))
    }
}

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
    let p1 = Fp::random_dense::<7, 2>(&mut rng, None);
    let one = Dense::<Fp, 7, 2>::one();
    let p2 = p1.clone() * one.clone();
    assert_eq!(p1.clone(), p2);
    let p3 = one * p1.clone();
    assert_eq!(p1.clone(), p3);
}

#[test]
fn test_mul_by_zero() {
    let mut rng = o1_utils::tests::make_test_rng(None);
    let p1 = Fp::random_dense::<5, 4>(&mut rng, None);
    let zero = Dense::<Fp, 5, 4>::zero();
    let p2 = p1.clone() * zero.clone();
    assert_eq!(zero, p2);
    let p3 = zero.clone() * p1.clone();
    assert_eq!(zero.clone(), p3);
}

#[test]
fn test_add_zero() {
    let mut rng = o1_utils::tests::make_test_rng(None);
    let p1 = Fp::random_dense::<3, 4>(&mut rng, None);

    let zero = Dense::<Fp, 3, 4>::zero();
    let p2 = p1.clone() + zero.clone();
    assert_eq!(p1.clone(), p2);
    let p3 = zero.clone() + p1.clone();
    assert_eq!(p1.clone(), p3);
}

#[test]
fn test_double_is_add_twice() {
    let mut rng = o1_utils::tests::make_test_rng(None);
    let p1 = Fp::random_dense::<3, 4>(&mut rng, None);
    let p2 = p1.clone() + p1.clone();
    let p3 = p1.clone().double();
    assert_eq!(p2, p3);
}

#[test]
fn test_sub_zero() {
    let mut rng = o1_utils::tests::make_test_rng(None);
    let p1 = Fp::random_dense::<3, 4>(&mut rng, None);
    let zero = Dense::<Fp, 3, 4>::zero();
    let p2 = p1.clone() - zero.clone();
    assert_eq!(p1.clone(), p2);
}

#[test]
fn test_neg() {
    let mut rng = o1_utils::tests::make_test_rng(None);
    let p1 = Fp::random_dense::<3, 4>(&mut rng, None);
    let p2 = -p1.clone();

    let sum = p1.clone() + p2.clone();
    assert_eq!(sum, Dense::<Fp, 3, 4>::zero());

    let p3 = -p2;
    assert_eq!(p1, p3);

    let zero = Dense::<Fp, 3, 4>::zero();
    let neg_zero = -zero.clone();
    assert_eq!(zero, neg_zero);
}

#[test]
fn test_neg_ref() {
    let mut rng = o1_utils::tests::make_test_rng(None);
    let p1 = Fp::random_dense::<3, 4>(&mut rng, None);
    let p2 = -&p1;

    let sum = p1.clone() + p2.clone();
    assert_eq!(sum, Dense::<Fp, 3, 4>::zero());

    let p3 = -&p2;
    assert_eq!(p1, p3);
}

#[test]
fn test_mul_by_scalar() {
    let mut rng = o1_utils::tests::make_test_rng(None);
    let p1 = Fp::random_dense::<4, 5>(&mut rng, None);
    let mut p2 = Dense::<Fp, 4, 5>::zero();
    let c = Fp::rand(&mut rng);
    p2[0] = c;
    assert_eq!(p2 * p1.clone(), p1.clone().mul_by_scalar(c))
}

#[test]
fn test_mul_by_scalar_with_zero() {
    let mut rng = o1_utils::tests::make_test_rng(None);
    let p1 = Fp::random_dense::<4, 5>(&mut rng, None);
    let c = Fp::zero();
    assert_eq!(p1.mul_by_scalar(c), Dense::<Fp, 4, 5>::zero())
}

#[test]
fn test_mul_by_scalar_with_one() {
    let mut rng = o1_utils::tests::make_test_rng(None);
    let p1 = Fp::random_dense::<4, 5>(&mut rng, None);
    let c = Fp::one();
    assert_eq!(p1.mul_by_scalar(c), p1)
}

#[test]
fn test_evaluation_zero_polynomial() {
    let mut rng = o1_utils::tests::make_test_rng(None);
    let random_evaluation = Fp::random_evaluation::<4>(&mut rng);
    let zero = Dense::<Fp, 4, 5>::zero();
    let evaluation = zero.eval(&random_evaluation);
    assert_eq!(evaluation, Fp::zero());
}

#[test]
fn test_evaluation_constant_polynomial() {
    let mut rng = o1_utils::tests::make_test_rng(None);
    let random_evaluation = Fp::random_evaluation::<4>(&mut rng);
    let cst = Fp::rand(&mut rng);
    let zero = Dense::<Fp, 4, 5>::from(cst);
    let evaluation = zero.eval(&random_evaluation);
    assert_eq!(evaluation, cst);
}

#[test]
fn test_eval_pbt_add() {
    let mut rng = o1_utils::tests::make_test_rng(None);
    let random_evaluation = Fp::random_evaluation::<6>(&mut rng);
    let p1 = Fp::random_dense::<6, 4>(&mut rng, None);
    let p2 = Fp::random_dense::<6, 4>(&mut rng, None);
    let p3 = p1.clone() + p2.clone();
    let eval_p1 = p1.eval(&random_evaluation);
    let eval_p2 = p2.eval(&random_evaluation);
    let eval_p3 = p3.eval(&random_evaluation);
    assert_eq!(eval_p3, eval_p1 + eval_p2);
}

#[test]
fn test_eval_pbt_sub() {
    let mut rng = o1_utils::tests::make_test_rng(None);
    let random_evaluation = Fp::random_evaluation::<6>(&mut rng);
    let p1 = Fp::random_dense::<6, 4>(&mut rng, None);
    let p2 = Fp::random_dense::<6, 4>(&mut rng, None);
    let p3 = p1.clone() - p2.clone();
    let eval_p1 = p1.eval(&random_evaluation);
    let eval_p2 = p2.eval(&random_evaluation);
    let eval_p3 = p3.eval(&random_evaluation);
    assert_eq!(eval_p3, eval_p1 - eval_p2);
}

#[test]
fn test_eval_pbt_mul_by_scalar() {
    let mut rng = o1_utils::tests::make_test_rng(None);
    let random_evaluation = Fp::random_evaluation::<6>(&mut rng);
    let p1 = Fp::random_dense::<6, 4>(&mut rng, None);
    let c = Fp::rand(&mut rng);
    let p2 = p1.clone() * Dense::<Fp, 6, 4>::from(c);
    let eval_p1 = p1.eval(&random_evaluation);
    let eval_p2 = p2.eval(&random_evaluation);
    assert_eq!(eval_p2, eval_p1 * c);
}

#[test]
fn test_eval_pbt_neg() {
    let mut rng = o1_utils::tests::make_test_rng(None);
    let random_evaluation = Fp::random_evaluation::<6>(&mut rng);
    let p1 = Fp::random_dense::<6, 4>(&mut rng, None);
    let p2 = -p1.clone();
    let eval_p1 = p1.eval(&random_evaluation);
    let eval_p2 = p2.eval(&random_evaluation);
    assert_eq!(eval_p2, -eval_p1);
}

#[test]
fn test_prime_increase_degree() {
    let mut rng = o1_utils::tests::make_test_rng(None);
    let p1 = Fp::random_dense::<6, 2>(&mut rng, None);
    {
        let p1_prime = p1.increase_degree::<3>();
        let random_evaluation = Fp::random_evaluation::<6>(&mut rng);
        assert_eq!(
            p1.eval(&random_evaluation),
            p1_prime.eval(&random_evaluation)
        );
    }
    {
        let p1_prime = p1.increase_degree::<4>();
        let random_evaluation = Fp::random_evaluation::<6>(&mut rng);
        assert_eq!(
            p1.eval(&random_evaluation),
            p1_prime.eval(&random_evaluation)
        );
    }
    {
        let p1_prime = p1.increase_degree::<5>();
        let random_evaluation = Fp::random_evaluation::<6>(&mut rng);
        assert_eq!(
            p1.eval(&random_evaluation),
            p1_prime.eval(&random_evaluation)
        );
    }
}

#[test]
fn test_degree_constant() {
    let mut rng = o1_utils::tests::make_test_rng(None);
    let c = Fp::rand(&mut rng);
    let p = Dense::<Fp, 4, 5>::from(c);
    let degree = unsafe { p.degree() };
    assert_eq!(degree, 0);

    let p = Dense::<Fp, 4, 5>::zero();
    let degree = unsafe { p.degree() };
    assert_eq!(degree, 0);
}

#[test]
fn test_degree_random_degree() {
    let mut rng = o1_utils::tests::make_test_rng(None);
    let max_degree: usize = rng.gen_range(1..5);
    let p = Fp::random_dense::<4, 5>(&mut rng, Some(max_degree));
    let degree = unsafe { p.degree() };
    assert!(degree <= max_degree);

    let max_degree: usize = rng.gen_range(1..20);
    let p = Fp::random_dense::<1, 20>(&mut rng, Some(max_degree));
    let degree = unsafe { p.degree() };
    assert!(degree <= max_degree);
}

#[test]
fn test_is_constant() {
    let mut rng = o1_utils::tests::make_test_rng(None);
    let c = Fp::rand(&mut rng);
    let p = Dense::<Fp, 4, 5>::from(c);
    assert!(p.is_constant());

    let p = Dense::<Fp, 4, 5>::zero();
    assert!(p.is_constant());

    let p = Dense::<Fp, 4, 5>::from_variable(2_usize);
    assert!(!p.is_constant());

    let p = Dense::<Fp, 4, 5>::from_variable(3_usize);
    assert!(!p.is_constant());

    let p = Fp::random_dense::<4, 5>(&mut rng, None);
    assert!(!p.is_constant());
}

#[test]
fn test_mvpoly_add_degree_pbt() {
    let mut rng = o1_utils::tests::make_test_rng(None);
    let degree = rng.gen_range(1..5);
    let p1 = Fp::random_dense::<4, 5>(&mut rng, Some(degree));
    let p2 = Fp::random_dense::<4, 5>(&mut rng, Some(degree));
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
    let p1 = Fp::random_dense::<4, 5>(&mut rng, Some(degree));
    let p2 = Fp::random_dense::<4, 5>(&mut rng, Some(degree));
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
    let p1 = Fp::random_dense::<4, 5>(&mut rng, Some(degree));
    let p2 = -p1.clone();
    let degree_p1 = unsafe { p1.degree() };
    let degree_p2 = unsafe { p2.degree() };
    assert_eq!(degree_p1, degree_p2);
}

#[test]
fn test_mvpoly_mul_by_scalar_degree_pbt() {
    let mut rng = o1_utils::tests::make_test_rng(None);
    let degree = rng.gen_range(1..5);
    let p1 = Fp::random_dense::<4, 5>(&mut rng, Some(degree));
    let c = Fp::rand(&mut rng);
    let p2 = p1.clone() * Dense::<Fp, 4, 5>::from(c);
    let degree_p1 = unsafe { p1.degree() };
    let degree_p2 = unsafe { p2.degree() };
    assert!(degree_p2 <= degree_p1);
}

#[test]
fn test_mvpoly_mul_degree_pbt() {
    let mut rng = o1_utils::tests::make_test_rng(None);
    let degree = rng.gen_range(1..3);
    let p1 = Fp::random_dense::<4, 6>(&mut rng, Some(degree));
    let p2 = Fp::random_dense::<4, 6>(&mut rng, Some(degree));
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
    let p1 = Fp::random_dense::<4, 6>(&mut rng, Some(max_degree));
    let p2 = Fp::random_dense::<4, 6>(&mut rng, Some(max_degree));
    let p3 = p1.clone() * p2.clone();
    let random_evaluation = Fp::random_evaluation::<4>(&mut rng);
    let eval_p1 = p1.eval(&random_evaluation);
    let eval_p2 = p2.eval(&random_evaluation);
    let eval_p3 = p3.eval(&random_evaluation);
    assert_eq!(eval_p3, eval_p1 * eval_p2);
}

#[test]
fn test_mvpoly_mul_pbt() {
    let mut rng = o1_utils::tests::make_test_rng(None);
    let max_degree = rng.gen_range(1..3);
    let p1 = Fp::random_dense::<4, 6>(&mut rng, Some(max_degree));
    let p2 = Fp::random_dense::<4, 6>(&mut rng, Some(max_degree));
    assert_eq!(p1.clone() * p2.clone(), p2.clone() * p1.clone());
}

#[test]
fn test_can_be_printed_with_debug() {
    let mut rng = o1_utils::tests::make_test_rng(None);
    let p1 = Fp::random_dense::<2, 2>(&mut rng, None);
    println!("{:?}", p1);
}

#[test]
fn test_is_zero() {
    let mut rng = o1_utils::tests::make_test_rng(None);
    let p1 = Dense::<Fp, 4, 6>::zero();
    assert!(p1.is_zero());

    let p2 = Fp::random_dense::<4, 6>(&mut rng, None);
    assert!(!p2.is_zero());
}
