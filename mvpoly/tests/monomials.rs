use ark_ff::{Field, One, UniformRand, Zero};
use kimchi::circuits::{
    berkeley_columns::BerkeleyChallengeTerm,
    expr::{ConstantExpr, Expr, ExprInner, Variable},
    gate::CurrOrNext,
};
use mina_curves::pasta::Fp;
use mvpoly::{monomials::Sparse, MVPoly};
use rand::Rng;

#[test]
fn test_mul_by_one() {
    mvpoly::pbt::test_mul_by_one::<Fp, 7, 2, Sparse<Fp, 7, 2>>();
}

#[test]
fn test_mul_by_zero() {
    mvpoly::pbt::test_mul_by_zero::<Fp, 5, 4, Sparse<Fp, 5, 4>>();
}

#[test]
fn test_add_zero() {
    mvpoly::pbt::test_add_zero::<Fp, 3, 4, Sparse<Fp, 3, 4>>();
}

#[test]
fn test_double_is_add_twice() {
    mvpoly::pbt::test_double_is_add_twice::<Fp, 3, 4, Sparse<Fp, 3, 4>>();
}

#[test]
fn test_sub_zero() {
    mvpoly::pbt::test_sub_zero::<Fp, 3, 4, Sparse<Fp, 3, 4>>();
}

#[test]
fn test_neg() {
    mvpoly::pbt::test_neg::<Fp, 3, 4, Sparse<Fp, 3, 4>>();
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
    mvpoly::pbt::test_eval_pbt_mul_by_scalar::<Fp, 6, 4, Sparse<Fp, 6, 4>>();
}

#[test]
fn test_eval_pbt_neg() {
    mvpoly::pbt::test_eval_pbt_neg::<Fp, 6, 4, Sparse<Fp, 6, 4>>();
}

#[test]
fn test_neg_ref() {
    mvpoly::pbt::test_neg_ref::<Fp, 3, 4, Sparse<Fp, 3, 4>>();
}

#[test]
fn test_mul_by_scalar() {
    mvpoly::pbt::test_mul_by_scalar::<Fp, 4, 5, Sparse<Fp, 4, 5>>();
}

#[test]
fn test_mul_by_scalar_with_zero() {
    mvpoly::pbt::test_mul_by_scalar_with_zero::<Fp, 4, 5, Sparse<Fp, 4, 5>>();
}

#[test]
fn test_mul_by_scalar_with_one() {
    mvpoly::pbt::test_mul_by_scalar_with_one::<Fp, 4, 5, Sparse<Fp, 4, 5>>();
}

#[test]
fn test_evaluation_zero_polynomial() {
    mvpoly::pbt::test_evaluation_zero_polynomial::<Fp, 4, 5, Sparse<Fp, 4, 5>>();
}

#[test]
fn test_evaluation_constant_polynomial() {
    mvpoly::pbt::test_evaluation_constant_polynomial::<Fp, 4, 5, Sparse<Fp, 4, 5>>();
}

#[test]
fn test_degree_constant() {
    mvpoly::pbt::test_degree_constant::<Fp, 4, 5, Sparse<Fp, 4, 5>>();
}

#[test]
fn test_degree_random_degree() {
    mvpoly::pbt::test_degree_random_degree::<Fp, 1, 7, Sparse<Fp, 1, 7>>();
    mvpoly::pbt::test_degree_random_degree::<Fp, 3, 5, Sparse<Fp, 3, 5>>();
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
    mvpoly::pbt::test_mvpoly_add_degree_pbt::<Fp, 4, 5, Sparse<Fp, 4, 5>>();
}

#[test]
fn test_mvpoly_sub_degree_pbt() {
    mvpoly::pbt::test_mvpoly_sub_degree_pbt::<Fp, 4, 5, Sparse<Fp, 4, 5>>();
}

#[test]
fn test_mvpoly_neg_degree_pbt() {
    mvpoly::pbt::test_mvpoly_neg_degree_pbt::<Fp, 4, 5, Sparse<Fp, 4, 5>>();
}

#[test]
fn test_mvpoly_mul_by_scalar_degree_pbt() {
    mvpoly::pbt::test_mvpoly_mul_by_scalar_degree_pbt::<Fp, 4, 5, Sparse<Fp, 4, 5>>();
}

#[test]
fn test_mvpoly_mul_degree_pbt() {
    mvpoly::pbt::test_mvpoly_mul_degree_pbt::<Fp, 4, 6, Sparse<Fp, 4, 6>>();
}

#[test]
fn test_mvpoly_mul_eval_pbt() {
    mvpoly::pbt::test_mvpoly_mul_eval_pbt::<Fp, 4, 6, Sparse<Fp, 4, 6>>();
}

#[test]
fn test_mvpoly_mul_pbt() {
    mvpoly::pbt::test_mvpoly_mul_pbt::<Fp, 4, 6, Sparse<Fp, 4, 6>>();
}

#[test]
fn test_can_be_printed_with_debug() {
    mvpoly::pbt::test_can_be_printed_with_debug::<Fp, 2, 2, Sparse<Fp, 2, 2>>();
}

#[test]
fn test_is_zero() {
    mvpoly::pbt::test_is_zero::<Fp, 4, 6, Sparse<Fp, 4, 6>>();
}

#[test]
fn test_homogeneous_eval() {
    mvpoly::pbt::test_homogeneous_eval::<Fp, 4, 2, Sparse<Fp, 4, 2>>();
}

#[test]
fn test_add_monomial() {
    mvpoly::pbt::test_add_monomial::<Fp, 4, 2, Sparse<Fp, 4, 2>>();
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

// The cross-terms of a sum of polynomials is the sum of the cross-terms, per
// power.
#[test]
fn test_mvpoly_pbt_cross_terms_addition() {
    let mut rng = o1_utils::tests::make_test_rng(None);
    let p1 = unsafe { Sparse::<Fp, 4, 4>::random(&mut rng, None) };
    let p2 = unsafe { Sparse::<Fp, 4, 4>::random(&mut rng, None) };
    let p = p1.clone() + p2.clone();

    let random_eval1: [Fp; 4] = std::array::from_fn(|_| Fp::rand(&mut rng));
    let random_eval2: [Fp; 4] = std::array::from_fn(|_| Fp::rand(&mut rng));
    let u1 = Fp::rand(&mut rng);
    let u2 = Fp::rand(&mut rng);

    let cross_terms1 = p1.compute_cross_terms(&random_eval1, &random_eval2, u1, u2);
    let cross_terms2 = p2.compute_cross_terms(&random_eval1, &random_eval2, u1, u2);
    let cross_terms = p.compute_cross_terms(&random_eval1, &random_eval2, u1, u2);

    let cross_terms_sum =
        cross_terms1
            .iter()
            .fold(cross_terms2.clone(), |mut acc, (power, term)| {
                acc.entry(*power)
                    .and_modify(|v| *v += term)
                    .or_insert(*term);
                acc
            });
    assert_eq!(cross_terms, cross_terms_sum);
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
    mvpoly::pbt::test_is_multilinear::<Fp, 6, 2, Sparse<Fp, 6, 2>>();
}

#[test]
fn test_increase_number_of_variables() {
    let mut rng = o1_utils::tests::make_test_rng(None);
    let p1: Sparse<Fp, 4, 2> = unsafe { Sparse::<Fp, 4, 2>::random(&mut rng, None) };

    let p2: Result<Sparse<Fp, 5, 2>, String> = p1.into();
    p2.unwrap();
}

#[test]
fn test_pbt_increase_number_of_variables_with_addition() {
    let mut rng = o1_utils::tests::make_test_rng(None);
    let p1: Sparse<Fp, 4, 2> = unsafe { Sparse::<Fp, 4, 2>::random(&mut rng, None) };
    let p2: Sparse<Fp, 4, 2> = unsafe { Sparse::<Fp, 4, 2>::random(&mut rng, None) };

    let lhs: Sparse<Fp, 5, 2> = {
        let p: Result<Sparse<Fp, 5, 2>, String> = (p1.clone() + p2.clone()).into();
        p.unwrap()
    };

    let rhs: Sparse<Fp, 5, 2> = {
        let p1: Result<Sparse<Fp, 5, 2>, String> = p1.clone().into();
        let p2: Result<Sparse<Fp, 5, 2>, String> = p2.clone().into();
        p1.unwrap() + p2.unwrap()
    };

    assert_eq!(lhs, rhs);
}

#[test]
fn test_pbt_increase_number_of_variables_zero_one_cst() {
    let mut rng = o1_utils::tests::make_test_rng(None);
    {
        let lhs_zero: Sparse<Fp, 5, 2> = {
            let p: Result<Sparse<Fp, 5, 2>, String> = Sparse::<Fp, 4, 2>::zero().into();
            p.unwrap()
        };
        let rhs_zero: Sparse<Fp, 5, 2> = Sparse::<Fp, 5, 2>::zero();
        assert_eq!(lhs_zero, rhs_zero);
    }

    {
        let lhs_one: Sparse<Fp, 5, 2> = {
            let p: Result<Sparse<Fp, 5, 2>, String> = Sparse::<Fp, 4, 2>::one().into();
            p.unwrap()
        };
        let rhs_one: Sparse<Fp, 5, 2> = Sparse::<Fp, 5, 2>::one();
        assert_eq!(lhs_one, rhs_one);
    }

    {
        let c = Fp::rand(&mut rng);
        let lhs: Sparse<Fp, 5, 2> = {
            let p: Result<Sparse<Fp, 5, 2>, String> = Sparse::<Fp, 4, 2>::from(c).into();
            p.unwrap()
        };
        let rhs: Sparse<Fp, 5, 2> = Sparse::<Fp, 5, 2>::from(c);
        assert_eq!(lhs, rhs);
    }
}

#[test]
fn test_build_from_variable() {
    #[derive(Clone, Copy, PartialEq)]
    enum Column {
        X(usize),
    }

    impl From<Column> for usize {
        fn from(val: Column) -> usize {
            match val {
                Column::X(i) => i,
            }
        }
    }

    let mut rng = o1_utils::tests::make_test_rng(None);
    let idx: usize = rng.gen_range(0..4);
    let p = Sparse::<Fp, 4, 3>::from_variable(Column::X(idx));

    let eval: [Fp; 4] = std::array::from_fn(|_i| Fp::rand(&mut rng));

    assert_eq!(p.eval(&eval), eval[idx]);
}

/// As a reminder, here are the equations to compute the addition of two
/// different points `P1 = (X1, Y1)` and `P2 = (X2, Y2)`. Let `P3 = (X3,
/// Y3) = P1 + P2`.
///
/// ```text
/// - λ = (Y1 - Y2) / (X1 - X2)
/// - X3 = λ^2 - X1 - X2
/// - Y3 = λ (X1 - X3) - Y1
/// ```
///
/// Therefore, the addition of elliptic curve points can be computed using the
/// following degree-2 constraints
///
/// ```text
/// - Constraint 1: λ (X1 - X2) - Y1 + Y2 = 0
/// - Constraint 2: X3 + X1 + X2 - λ^2 = 0
/// - Constraint 3: Y3 - λ (X1 - X3) + Y1 = 0
/// ```
#[test]
fn test_from_expr_ec_addition() {
    // Simulate a real usecase
    // The following lines/design look similar to the ones we use in
    // o1vm/arrabiata
    #[derive(Clone, Copy, PartialEq)]
    enum Column {
        X(usize),
    }

    impl From<Column> for usize {
        fn from(val: Column) -> usize {
            match val {
                Column::X(i) => i,
            }
        }
    }

    struct Constraint {
        idx: usize,
    }

    trait Interpreter {
        type Position: Clone + Copy;

        type Variable: Clone
            + std::ops::Add<Self::Variable, Output = Self::Variable>
            + std::ops::Sub<Self::Variable, Output = Self::Variable>
            + std::ops::Mul<Self::Variable, Output = Self::Variable>;

        fn allocate(&mut self) -> Self::Position;

        // Simulate fetching/reading a value from outside
        // In the case of the witness, it will be getting a value from the
        // environment
        fn fetch(&self, pos: Self::Position) -> Self::Variable;
    }

    impl Interpreter for Constraint {
        type Position = Column;

        type Variable = Expr<ConstantExpr<Fp, BerkeleyChallengeTerm>, Column>;

        fn allocate(&mut self) -> Self::Position {
            let col = Column::X(self.idx);
            self.idx += 1;
            col
        }

        fn fetch(&self, col: Self::Position) -> Self::Variable {
            Expr::Atom(ExprInner::Cell(Variable {
                col,
                row: CurrOrNext::Curr,
            }))
        }
    }

    impl Constraint {
        fn new() -> Self {
            Self { idx: 0 }
        }
    }

    let mut interpreter = Constraint::new();
    // Constraints for elliptic curve addition, without handling the case of the
    // point at infinity or double
    let lambda = {
        let pos = interpreter.allocate();
        interpreter.fetch(pos)
    };
    let x1 = {
        let pos = interpreter.allocate();
        interpreter.fetch(pos)
    };
    let x2 = {
        let pos = interpreter.allocate();
        interpreter.fetch(pos)
    };

    let y1 = {
        let pos = interpreter.allocate();
        interpreter.fetch(pos)
    };
    let y2 = {
        let pos = interpreter.allocate();
        interpreter.fetch(pos)
    };

    let x3 = {
        let pos = interpreter.allocate();
        interpreter.fetch(pos)
    };
    let y3 = {
        let pos = interpreter.allocate();
        interpreter.fetch(pos)
    };

    // Check we can convert into a Sparse polynomial.
    // We have 7 variables, maximum degree 2.
    // We test by evaluating at a random point.
    let mut rng = o1_utils::tests::make_test_rng(None);
    {
        // - Constraint 1: λ (X1 - X2) - Y1 + Y2 = 0
        let expression = lambda.clone() * (x1.clone() - x2.clone()) - (y1.clone() - y2.clone());

        let p = Sparse::<Fp, 7, 2>::from_expr(expression);
        let random_evaluation: [Fp; 7] = std::array::from_fn(|_| Fp::rand(&mut rng));
        let eval = p.eval(&random_evaluation);
        let exp_eval = {
            random_evaluation[0] * (random_evaluation[1] - random_evaluation[2])
                - (random_evaluation[3] - random_evaluation[4])
        };
        assert_eq!(eval, exp_eval);
    }

    {
        // - Constraint 2: X3 + X1 + X2 - λ^2 = 0
        let expr = x3.clone() + x1.clone() + x2.clone() - lambda.clone() * lambda.clone();
        let p = Sparse::<Fp, 7, 2>::from_expr(expr);
        let random_evaluation: [Fp; 7] = std::array::from_fn(|_| Fp::rand(&mut rng));
        let eval = p.eval(&random_evaluation);
        let exp_eval = {
            random_evaluation[5] + random_evaluation[1] + random_evaluation[2]
                - random_evaluation[0] * random_evaluation[0]
        };
        assert_eq!(eval, exp_eval);
    }
    {
        // - Constraint 3: Y3 - λ (X1 - X3) + Y1 = 0
        let expr = y3.clone() - lambda.clone() * (x1.clone() - x3.clone()) + y1.clone();
        let p = Sparse::<Fp, 7, 2>::from_expr(expr);
        let random_evaluation: [Fp; 7] = std::array::from_fn(|_| Fp::rand(&mut rng));
        let eval = p.eval(&random_evaluation);
        let exp_eval = {
            random_evaluation[6]
                - random_evaluation[0] * (random_evaluation[1] - random_evaluation[5])
                + random_evaluation[3]
        };
        assert_eq!(eval, exp_eval);
    }
}
