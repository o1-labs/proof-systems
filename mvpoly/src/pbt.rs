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
//! fn test_mul_by_one() {
//!     mvpoly::pbt::test_mul_by_one::<Fp, 2, 2, Dense<Fp, 2, 2>>();
//!     mvpoly::pbt::test_mul_by_one::<Fp, 4, 2, Dense<Fp, 4, 2>>();
//! }
//! ```

use crate::MVPoly;
use ark_ff::PrimeField;
use rand::{seq::SliceRandom, Rng};
use std::ops::Neg;

pub fn test_mul_by_one<F: PrimeField, const N: usize, const D: usize, T: MVPoly<F, N, D>>() {
    let mut rng = o1_utils::tests::make_test_rng(None);
    let p1 = unsafe { T::random(&mut rng, None) };
    let one = T::one();
    let p2 = p1.clone() * one.clone();
    assert_eq!(p1.clone(), p2);
    let p3 = one * p1.clone();
    assert_eq!(p1.clone(), p3);
}

pub fn test_mul_by_zero<F: PrimeField, const N: usize, const D: usize, T: MVPoly<F, N, D>>() {
    let mut rng = o1_utils::tests::make_test_rng(None);
    let p1 = unsafe { T::random(&mut rng, None) };
    let zero = T::zero();
    let p2 = p1.clone() * zero.clone();
    assert_eq!(zero, p2);
    let p3 = zero.clone() * p1.clone();
    assert_eq!(zero.clone(), p3);
}

pub fn test_add_zero<F: PrimeField, const N: usize, const D: usize, T: MVPoly<F, N, D>>() {
    let mut rng = o1_utils::tests::make_test_rng(None);
    let p1 = unsafe { T::random(&mut rng, None) };
    let zero = T::zero();
    let p2 = p1.clone() + zero.clone();
    assert_eq!(p1.clone(), p2);
    let p3 = zero.clone() + p1.clone();
    assert_eq!(p1.clone(), p3);
}

pub fn test_double_is_add_twice<
    F: PrimeField,
    const N: usize,
    const D: usize,
    T: MVPoly<F, N, D>,
>() {
    let mut rng = o1_utils::tests::make_test_rng(None);
    let p1 = unsafe { T::random(&mut rng, None) };
    let p2 = p1.clone() + p1.clone();
    let p3 = p1.clone().double();
    assert_eq!(p2, p3);
}

pub fn test_sub_zero<F: PrimeField, const N: usize, const D: usize, T: MVPoly<F, N, D>>() {
    let mut rng = o1_utils::tests::make_test_rng(None);
    let p1 = unsafe { T::random(&mut rng, None) };
    let zero = T::zero();
    let p2 = p1.clone() - zero.clone();
    assert_eq!(p1.clone(), p2);
}

pub fn test_neg<F: PrimeField, const N: usize, const D: usize, T: MVPoly<F, N, D>>() {
    let mut rng = o1_utils::tests::make_test_rng(None);
    let p1 = unsafe { T::random(&mut rng, None) };
    let p2 = -p1.clone();
    // Test that p1 + (-p1) = 0
    let sum = p1.clone() + p2.clone();
    assert_eq!(sum, T::zero());
    // Test that -(-p1) = p1
    let p3 = -p2;
    assert_eq!(p1, p3);
    // Test negation of zero
    let zero = T::zero();
    let neg_zero = -zero.clone();
    assert_eq!(zero, neg_zero);
}

pub fn test_eval_pbt_add<F: PrimeField, const N: usize, const D: usize, T: MVPoly<F, N, D>>()
where
    for<'a> &'a T: std::ops::Add<T, Output = T> + std::ops::Add<&'a T, Output = T>,
{
    let mut rng = o1_utils::tests::make_test_rng(None);
    let random_evaluation: [F; N] = std::array::from_fn(|_| F::rand(&mut rng));
    let p1 = unsafe { T::random(&mut rng, None) };
    let p2 = unsafe { T::random(&mut rng, None) };
    let eval_p1 = p1.eval(&random_evaluation);
    let eval_p2 = p2.eval(&random_evaluation);
    {
        let p3 = p1.clone() + p2.clone();
        let eval_p3 = p3.eval(&random_evaluation);
        assert_eq!(eval_p3, eval_p1 + eval_p2);
    }
    {
        let p3 = p1.clone() + &p2;
        let eval_p3 = p3.eval(&random_evaluation);
        assert_eq!(eval_p3, eval_p1 + eval_p2);
    }
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
}

pub fn test_eval_pbt_sub<F: PrimeField, const N: usize, const D: usize, T: MVPoly<F, N, D>>()
where
    for<'a> &'a T: std::ops::Sub<T, Output = T> + std::ops::Sub<&'a T, Output = T>,
{
    let mut rng = o1_utils::tests::make_test_rng(None);
    let random_evaluation: [F; N] = std::array::from_fn(|_| F::rand(&mut rng));
    let p1 = unsafe { T::random(&mut rng, None) };
    let p2 = unsafe { T::random(&mut rng, None) };
    let eval_p1 = p1.eval(&random_evaluation);
    let eval_p2 = p2.eval(&random_evaluation);
    {
        let p3 = p1.clone() - p2.clone();
        let eval_p3 = p3.eval(&random_evaluation);
        assert_eq!(eval_p3, eval_p1 - eval_p2);
    }
    {
        let p3 = p1.clone() - &p2;
        let eval_p3 = p3.eval(&random_evaluation);
        assert_eq!(eval_p3, eval_p1 - eval_p2);
    }
    {
        let p3 = &p1 - p2.clone();
        let eval_p3 = p3.eval(&random_evaluation);
        assert_eq!(eval_p3, eval_p1 - eval_p2);
    }
    {
        let p3 = &p1 - &p2;
        let eval_p3 = p3.eval(&random_evaluation);
        assert_eq!(eval_p3, eval_p1 - eval_p2);
    }
}

pub fn test_eval_pbt_mul_by_scalar<
    F: PrimeField,
    const N: usize,
    const D: usize,
    T: MVPoly<F, N, D>,
>() {
    let mut rng = o1_utils::tests::make_test_rng(None);
    let random_evaluation: [F; N] = std::array::from_fn(|_| F::rand(&mut rng));
    let p1 = unsafe { T::random(&mut rng, None) };
    let c = F::rand(&mut rng);
    let p2 = p1.clone() * T::from(c);
    let eval_p1 = p1.eval(&random_evaluation);
    let eval_p2 = p2.eval(&random_evaluation);
    assert_eq!(eval_p2, eval_p1 * c);
}

pub fn test_eval_pbt_neg<F: PrimeField, const N: usize, const D: usize, T: MVPoly<F, N, D>>() {
    let mut rng = o1_utils::tests::make_test_rng(None);
    let random_evaluation: [F; N] = std::array::from_fn(|_| F::rand(&mut rng));
    let p1 = unsafe { T::random(&mut rng, None) };
    let p2 = -p1.clone();
    let eval_p1 = p1.eval(&random_evaluation);
    let eval_p2 = p2.eval(&random_evaluation);
    assert_eq!(eval_p2, -eval_p1);
}

pub fn test_neg_ref<F: PrimeField, const N: usize, const D: usize, T: MVPoly<F, N, D>>()
where
    for<'a> &'a T: Neg<Output = T>,
{
    let mut rng = o1_utils::tests::make_test_rng(None);
    let p1 = unsafe { T::random(&mut rng, None) };
    let p2 = -&p1;
    // Test that p1 + (-&p1) = 0
    let sum = p1.clone() + p2.clone();
    assert_eq!(sum, T::zero());
    // Test that -(-&p1) = p1
    let p3 = -&p2;
    assert_eq!(p1, p3);
}

pub fn test_mul_by_scalar<F: PrimeField, const N: usize, const D: usize, T: MVPoly<F, N, D>>() {
    let mut rng = o1_utils::tests::make_test_rng(None);
    let p1 = unsafe { T::random(&mut rng, None) };
    let mut p2 = T::zero();
    let c = F::rand(&mut rng);
    p2.modify_monomial([0; N], c);
    assert_eq!(p2 * p1.clone(), p1.clone().mul_by_scalar(c));
}

pub fn test_mul_by_scalar_with_zero<
    F: PrimeField,
    const N: usize,
    const D: usize,
    T: MVPoly<F, N, D>,
>() {
    let mut rng = o1_utils::tests::make_test_rng(None);
    let p1 = unsafe { T::random(&mut rng, None) };
    let c = F::zero();
    assert_eq!(p1.mul_by_scalar(c), T::zero());
}

pub fn test_mul_by_scalar_with_one<
    F: PrimeField,
    const N: usize,
    const D: usize,
    T: MVPoly<F, N, D>,
>() {
    let mut rng = o1_utils::tests::make_test_rng(None);
    let p1 = unsafe { T::random(&mut rng, None) };
    let c = F::one();
    assert_eq!(p1.mul_by_scalar(c), p1);
}

pub fn test_evaluation_zero_polynomial<
    F: PrimeField,
    const N: usize,
    const D: usize,
    T: MVPoly<F, N, D>,
>() {
    let mut rng = o1_utils::tests::make_test_rng(None);
    let random_evaluation: [F; N] = std::array::from_fn(|_| F::rand(&mut rng));
    let zero = T::zero();
    let evaluation = zero.eval(&random_evaluation);
    assert_eq!(evaluation, F::zero());
}

pub fn test_evaluation_constant_polynomial<
    F: PrimeField,
    const N: usize,
    const D: usize,
    T: MVPoly<F, N, D>,
>() {
    let mut rng = o1_utils::tests::make_test_rng(None);
    let random_evaluation: [F; N] = std::array::from_fn(|_| F::rand(&mut rng));
    let cst = F::rand(&mut rng);
    let poly = T::from(cst);
    let evaluation = poly.eval(&random_evaluation);
    assert_eq!(evaluation, cst);
}

pub fn test_degree_constant<F: PrimeField, const N: usize, const D: usize, T: MVPoly<F, N, D>>() {
    let mut rng = o1_utils::tests::make_test_rng(None);
    let c = F::rand(&mut rng);
    let p = T::from(c);
    let degree = unsafe { p.degree() };
    assert_eq!(degree, 0);
    let p = T::zero();
    let degree = unsafe { p.degree() };
    assert_eq!(degree, 0);
}

pub fn test_degree_random_degree<
    F: PrimeField,
    const N: usize,
    const D: usize,
    T: MVPoly<F, N, D>,
>() {
    let mut rng = o1_utils::tests::make_test_rng(None);
    let max_degree: usize = rng.gen_range(1..D);
    let p = unsafe { T::random(&mut rng, Some(max_degree)) };
    let degree = unsafe { p.degree() };
    assert!(degree <= max_degree);
}

pub fn test_mvpoly_add_degree_pbt<
    F: PrimeField,
    const N: usize,
    const D: usize,
    T: MVPoly<F, N, D>,
>() {
    let mut rng = o1_utils::tests::make_test_rng(None);
    let degree = rng.gen_range(1..D);
    let p1 = unsafe { T::random(&mut rng, Some(degree)) };
    let p2 = unsafe { T::random(&mut rng, Some(degree)) };
    let p3 = p1.clone() + p2.clone();
    let degree_p1 = unsafe { p1.degree() };
    let degree_p2 = unsafe { p2.degree() };
    let degree_p3 = unsafe { p3.degree() };
    assert!(degree_p3 <= std::cmp::max(degree_p1, degree_p2));
}

pub fn test_mvpoly_sub_degree_pbt<
    F: PrimeField,
    const N: usize,
    const D: usize,
    T: MVPoly<F, N, D>,
>() {
    let mut rng = o1_utils::tests::make_test_rng(None);
    let degree = rng.gen_range(1..D);
    let p1 = unsafe { T::random(&mut rng, Some(degree)) };
    let p2 = unsafe { T::random(&mut rng, Some(degree)) };
    let p3 = p1.clone() - p2.clone();
    let degree_p1 = unsafe { p1.degree() };
    let degree_p2 = unsafe { p2.degree() };
    let degree_p3 = unsafe { p3.degree() };
    assert!(degree_p3 <= std::cmp::max(degree_p1, degree_p2));
}

pub fn test_mvpoly_neg_degree_pbt<
    F: PrimeField,
    const N: usize,
    const D: usize,
    T: MVPoly<F, N, D>,
>() {
    let mut rng = o1_utils::tests::make_test_rng(None);
    let degree = rng.gen_range(1..D);
    let p1 = unsafe { T::random(&mut rng, Some(degree)) };
    let p2 = -p1.clone();
    let degree_p1 = unsafe { p1.degree() };
    let degree_p2 = unsafe { p2.degree() };
    assert_eq!(degree_p1, degree_p2);
}

pub fn test_mvpoly_mul_by_scalar_degree_pbt<
    F: PrimeField,
    const N: usize,
    const D: usize,
    T: MVPoly<F, N, D>,
>() {
    let mut rng = o1_utils::tests::make_test_rng(None);
    let max_degree = rng.gen_range(1..D / 2);
    let p1 = unsafe { T::random(&mut rng, Some(max_degree)) };
    let c = F::rand(&mut rng);
    let p2 = p1.clone() * T::from(c);
    let degree_p1 = unsafe { p1.degree() };
    let degree_p2 = unsafe { p2.degree() };
    assert!(degree_p2 <= degree_p1);
}

pub fn test_mvpoly_mul_degree_pbt<
    F: PrimeField,
    const N: usize,
    const D: usize,
    T: MVPoly<F, N, D>,
>() {
    let mut rng = o1_utils::tests::make_test_rng(None);
    let max_degree = rng.gen_range(1..D / 2);
    let p1 = unsafe { T::random(&mut rng, Some(max_degree)) };
    let p2 = unsafe { T::random(&mut rng, Some(max_degree)) };
    let p3 = p1.clone() * p2.clone();
    let degree_p1 = unsafe { p1.degree() };
    let degree_p2 = unsafe { p2.degree() };
    let degree_p3 = unsafe { p3.degree() };
    assert!(degree_p3 <= degree_p1 + degree_p2);
}

pub fn test_mvpoly_mul_eval_pbt<
    F: PrimeField,
    const N: usize,
    const D: usize,
    T: MVPoly<F, N, D>,
>() {
    let mut rng = o1_utils::tests::make_test_rng(None);
    let max_degree = rng.gen_range(1..D / 2);
    let p1 = unsafe { T::random(&mut rng, Some(max_degree)) };
    let p2 = unsafe { T::random(&mut rng, Some(max_degree)) };
    let p3 = p1.clone() * p2.clone();
    let random_evaluation: [F; N] = std::array::from_fn(|_| F::rand(&mut rng));
    let eval_p1 = p1.eval(&random_evaluation);
    let eval_p2 = p2.eval(&random_evaluation);
    let eval_p3 = p3.eval(&random_evaluation);
    assert_eq!(eval_p3, eval_p1 * eval_p2);
}

pub fn test_mvpoly_mul_pbt<F: PrimeField, const N: usize, const D: usize, T: MVPoly<F, N, D>>() {
    let mut rng = o1_utils::tests::make_test_rng(None);
    let max_degree = rng.gen_range(1..D / 2);
    let p1 = unsafe { T::random(&mut rng, Some(max_degree)) };
    let p2 = unsafe { T::random(&mut rng, Some(max_degree)) };
    assert_eq!(p1.clone() * p2.clone(), p2.clone() * p1.clone());
}

pub fn test_can_be_printed_with_debug<
    F: PrimeField,
    const N: usize,
    const D: usize,
    T: MVPoly<F, N, D>,
>() {
    let mut rng = o1_utils::tests::make_test_rng(None);
    let p1 = unsafe { T::random(&mut rng, None) };
    println!("{:?}", p1);
}

pub fn test_is_zero<F: PrimeField, const N: usize, const D: usize, T: MVPoly<F, N, D>>() {
    let mut rng = o1_utils::tests::make_test_rng(None);
    let p1 = T::zero();
    assert!(p1.is_zero());
    let p2 = unsafe { T::random(&mut rng, None) };
    assert!(!p2.is_zero());
}

pub fn test_homogeneous_eval<F: PrimeField, const N: usize, const D: usize, T: MVPoly<F, N, D>>() {
    let mut rng = o1_utils::tests::make_test_rng(None);
    let random_eval = std::array::from_fn(|_| F::rand(&mut rng));
    let u = F::rand(&mut rng);

    // Homogeneous form is u^2
    let p1 = T::one();
    let homogenous_eval = p1.homogeneous_eval(&random_eval, u);
    assert_eq!(homogenous_eval, u * u);

    let mut p2 = T::zero();
    let mut exp1 = [0; N];
    exp1[0] = 1;
    p2.add_monomial(exp1, F::one());
    let homogenous_eval = p2.homogeneous_eval(&random_eval, u);
    assert_eq!(homogenous_eval, random_eval[0] * u);

    let mut p3 = T::zero();
    let mut exp2 = [0; N];
    exp2[1] = 1;
    p3.add_monomial(exp2, F::one());
    let homogenous_eval = p3.homogeneous_eval(&random_eval, u);
    assert_eq!(homogenous_eval, random_eval[1] * u);

    let mut p4 = T::zero();
    let mut exp3 = [0; N];
    exp3[0] = 1;
    exp3[1] = 1;
    p4.add_monomial(exp3, F::one());
    let homogenous_eval = p4.homogeneous_eval(&random_eval, u);
    assert_eq!(homogenous_eval, random_eval[0] * random_eval[1]);

    let mut p5 = T::zero();
    let mut exp4 = [0; N];
    exp4[0] = 2;
    p5.add_monomial(exp4, F::one());
    let homogenous_eval = p5.homogeneous_eval(&random_eval, u);
    assert_eq!(homogenous_eval, random_eval[0] * random_eval[0]);

    let mut p6 = T::zero();
    let mut exp5a = [0; N];
    let mut exp5b = [0; N];
    exp5a[1] = 2;
    exp5b[0] = 2;
    p6.add_monomial(exp5a, F::one());
    p6.add_monomial(exp5b, F::one());
    let homogenous_eval = p6.homogeneous_eval(&random_eval, u);
    assert_eq!(
        homogenous_eval,
        random_eval[1] * random_eval[1] + random_eval[0] * random_eval[0]
    );

    let mut p7 = T::zero();
    let mut exp6a = [0; N];
    let mut exp6b = [0; N];
    let mut exp6c = [0; N];
    exp6a[1] = 2;
    exp6b[0] = 2;
    exp6c[0] = 1;
    p7.add_monomial(exp6a, F::one());
    p7.add_monomial(exp6b, F::one());
    p7.add_monomial(exp6c, F::one());
    p7.add_monomial([0; N], F::from(42u32));
    let homogenous_eval = p7.homogeneous_eval(&random_eval, u);
    assert_eq!(
        homogenous_eval,
        random_eval[1] * random_eval[1]
            + random_eval[0] * random_eval[0]
            + u * random_eval[0]
            + u * u * F::from(42u32)
    );
}

pub fn test_add_monomial<F: PrimeField, const N: usize, const D: usize, T: MVPoly<F, N, D>>() {
    let mut rng = o1_utils::tests::make_test_rng(None);

    // Adding constant monomial one to zero
    let mut p1 = T::zero();
    p1.add_monomial([0; N], F::one());
    assert_eq!(p1, T::one());

    // Adding random constant monomial one to zero
    let mut p2 = T::zero();
    let random_c = F::rand(&mut rng);
    p2.add_monomial([0; N], random_c);
    assert_eq!(p2, T::from(random_c));

    let mut p3 = T::zero();
    let random_c1 = F::rand(&mut rng);
    let random_c2 = F::rand(&mut rng);
    // X1 + X2
    let mut exp1 = [0; N];
    let mut exp2 = [0; N];
    exp1[0] = 1;
    exp2[1] = 1;
    p3.add_monomial(exp1, random_c1);
    p3.add_monomial(exp2, random_c2);

    let random_eval = std::array::from_fn(|_| F::rand(&mut rng));
    let eval_p3 = p3.eval(&random_eval);
    let exp_eval_p3 = random_c1 * random_eval[0] + random_c2 * random_eval[1];
    assert_eq!(eval_p3, exp_eval_p3);

    let mut p4 = T::zero();
    let random_c1 = F::rand(&mut rng);
    let random_c2 = F::rand(&mut rng);
    // X1^2 + X2^2
    let mut exp1 = [0; N];
    let mut exp2 = [0; N];
    exp1[0] = 2;
    exp2[1] = 2;
    p4.add_monomial(exp1, random_c1);
    p4.add_monomial(exp2, random_c2);
    let eval_p4 = p4.eval(&random_eval);
    let exp_eval_p4 =
        random_c1 * random_eval[0] * random_eval[0] + random_c2 * random_eval[1] * random_eval[1];
    assert_eq!(eval_p4, exp_eval_p4);
}

pub fn test_is_multilinear<F: PrimeField, const N: usize, const D: usize, T: MVPoly<F, N, D>>() {
    let mut rng = o1_utils::tests::make_test_rng(None);

    // Test with zero polynomial
    let p1 = T::zero();
    assert!(p1.is_multilinear());

    // Test with a constant polynomial
    let c = F::rand(&mut rng);
    let p2 = T::from(c);
    assert!(p2.is_multilinear());

    // Test with a polynomial with one variable having a linear monomial
    {
        let mut p = T::zero();
        let c = F::rand(&mut rng);
        let idx = rng.gen_range(0..N);
        let monomials_exponents = std::array::from_fn(|i| if i == idx { 1 } else { 0 });
        p.add_monomial(monomials_exponents, c);
        assert!(p.is_multilinear());
    }

    // Test with a multilinear polynomial with random variables
    {
        let mut p = T::zero();
        let c = F::rand(&mut rng);
        let nb_var = rng.gen_range(0..D);
        let mut monomials_exponents: [usize; N] =
            std::array::from_fn(|i| if i <= nb_var { 1 } else { 0 });
        monomials_exponents.shuffle(&mut rng);
        p.add_monomial(monomials_exponents, c);
        assert!(p.is_multilinear());
    }
}

pub fn test_is_constant<F: PrimeField, const N: usize, const D: usize, T: MVPoly<F, N, D>>() {
    let mut rng = o1_utils::tests::make_test_rng(None);
    let c = F::rand(&mut rng);
    let p = T::from(c);
    assert!(p.is_constant());

    let p = T::zero();
    assert!(p.is_constant());

    let p = {
        let mut res = T::zero();
        let monomial: [usize; N] = std::array::from_fn(|i| if i == 0 { 1 } else { 0 });
        res.add_monomial(monomial, F::one());
        res
    };
    assert!(!p.is_constant());

    let p = {
        let mut res = T::zero();
        let monomial: [usize; N] = std::array::from_fn(|i| if i == 1 { 1 } else { 0 });
        res.add_monomial(monomial, F::one());
        res
    };
    assert!(!p.is_constant());

    // This might be flaky
    let p = unsafe { T::random(&mut rng, None) };
    assert!(!p.is_constant());
}
