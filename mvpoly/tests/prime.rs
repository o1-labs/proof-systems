use ark_ff::{One, UniformRand, Zero};
use kimchi::circuits::{
    expr::{BerkeleyChallengeTerm, ConstantExpr, Expr, ExprInner, Variable},
    gate::CurrOrNext,
};
use mina_curves::pasta::Fp;
use mvpoly::{prime::Dense, utils::PrimeNumberGenerator, MVPoly};
use rand::{seq::SliceRandom, Rng};

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
    mvpoly::pbt::test_mul_by_one::<Fp, 7, 2, Dense<Fp, 7, 2>>();
}

#[test]
fn test_mul_by_zero() {
    mvpoly::pbt::test_mul_by_zero::<Fp, 5, 4, Dense<Fp, 5, 4>>();
}

#[test]
fn test_add_zero() {
    mvpoly::pbt::test_add_zero::<Fp, 3, 4, Dense<Fp, 3, 4>>();
}

#[test]
fn test_double_is_add_twice() {
    mvpoly::pbt::test_double_is_add_twice::<Fp, 3, 4, Dense<Fp, 3, 4>>();
}

#[test]
fn test_sub_zero() {
    mvpoly::pbt::test_sub_zero::<Fp, 3, 4, Dense<Fp, 3, 4>>();
}

#[test]
fn test_neg() {
    mvpoly::pbt::test_neg::<Fp, 3, 4, Dense<Fp, 3, 4>>();
}

#[test]
fn test_eval_pbt_add() {
    mvpoly::pbt::test_eval_pbt_add::<Fp, 6, 4, Dense<Fp, 6, 4>>();
}

#[test]
fn test_eval_pbt_sub() {
    mvpoly::pbt::test_eval_pbt_sub::<Fp, 6, 4, Dense<Fp, 6, 4>>();
}

#[test]
fn test_eval_pbt_mul_by_scalar() {
    mvpoly::pbt::test_eval_pbt_mul_by_scalar::<Fp, 6, 4, Dense<Fp, 6, 4>>();
}

#[test]
fn test_eval_pbt_neg() {
    mvpoly::pbt::test_eval_pbt_neg::<Fp, 6, 4, Dense<Fp, 6, 4>>();
}

#[test]
fn test_neg_ref() {
    mvpoly::pbt::test_neg_ref::<Fp, 3, 4, Dense<Fp, 3, 4>>();
}

#[test]
fn test_mul_by_scalar() {
    mvpoly::pbt::test_mul_by_scalar::<Fp, 4, 5, Dense<Fp, 4, 5>>();
}

#[test]
fn test_mul_by_scalar_with_zero() {
    mvpoly::pbt::test_mul_by_scalar_with_zero::<Fp, 4, 5, Dense<Fp, 4, 5>>();
}

#[test]
fn test_mul_by_scalar_with_one() {
    mvpoly::pbt::test_mul_by_scalar_with_one::<Fp, 4, 5, Dense<Fp, 4, 5>>();
}

#[test]
fn test_mul_by_scalar_with_from() {
    let mut rng = o1_utils::tests::make_test_rng(None);
    let p = unsafe { Dense::<Fp, 4, 5>::random(&mut rng, None) };
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

#[test]
fn test_evaluation_zero_polynomial() {
    mvpoly::pbt::test_evaluation_zero_polynomial::<Fp, 4, 5, Dense<Fp, 4, 5>>();
}

#[test]
fn test_evaluation_constant_polynomial() {
    mvpoly::pbt::test_evaluation_constant_polynomial::<Fp, 4, 5, Dense<Fp, 4, 5>>();
}

#[test]
fn test_evaluation_predefined_polynomial() {
    // Evaluating at random points
    let mut rng = o1_utils::tests::make_test_rng(None);

    let random_evaluation: [Fp; 2] = std::array::from_fn(|_| Fp::rand(&mut rng));
    // P(X1, X2) = 2 + 3X1 + 4X2 + 5X1^2 + 6X1 X2 + 7 X2^2
    let p = Dense::<Fp, 2, 2>::from_coeffs(vec![
        Fp::from(2_u32),
        Fp::from(3_u32),
        Fp::from(4_u32),
        Fp::from(5_u32),
        Fp::from(6_u32),
        Fp::from(7_u32),
    ]);
    let exp_eval = Fp::from(2_u32)
        + Fp::from(3_u32) * random_evaluation[0]
        + Fp::from(4_u32) * random_evaluation[1]
        + Fp::from(5_u32) * random_evaluation[0] * random_evaluation[0]
        + Fp::from(6_u32) * random_evaluation[0] * random_evaluation[1]
        + Fp::from(7_u32) * random_evaluation[1] * random_evaluation[1];
    let evaluation = p.eval(&random_evaluation);
    assert_eq!(evaluation, exp_eval);
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
                Column::X(i) => {
                    let mut prime_gen = PrimeNumberGenerator::new();
                    prime_gen.get_nth_prime(i + 1)
                }
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

    // Check we can convert into a Dense polynomial using prime representation
    // We have 7 variables, maximum degree 2
    // We test by evaluating at a random point.
    let mut rng = o1_utils::tests::make_test_rng(None);
    {
        // - Constraint 1: λ (X1 - X2) - Y1 + Y2 = 0
        let expression = lambda.clone() * (x1.clone() - x2.clone()) - (y1.clone() - y2.clone());

        let p = Dense::<Fp, 7, 2>::from_expr(expression);
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
        let p = Dense::<Fp, 7, 2>::from_expr(expr);
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
        let p = Dense::<Fp, 7, 2>::from_expr(expr);
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

#[test]
pub fn test_prime_increase_degree() {
    let mut rng = o1_utils::tests::make_test_rng(None);
    let p1 = unsafe { Dense::<Fp, 6, 2>::random(&mut rng, None) };
    {
        let p1_prime = p1.increase_degree::<3>();
        let random_evaluation: [Fp; 6] = std::array::from_fn(|_| Fp::rand(&mut rng));
        assert_eq!(
            p1.eval(&random_evaluation),
            p1_prime.eval(&random_evaluation)
        );
    }
    {
        let p1_prime = p1.increase_degree::<4>();
        let random_evaluation: [Fp; 6] = std::array::from_fn(|_| Fp::rand(&mut rng));
        assert_eq!(
            p1.eval(&random_evaluation),
            p1_prime.eval(&random_evaluation)
        );
    }
    {
        let p1_prime = p1.increase_degree::<5>();
        let random_evaluation: [Fp; 6] = std::array::from_fn(|_| Fp::rand(&mut rng));
        assert_eq!(
            p1.eval(&random_evaluation),
            p1_prime.eval(&random_evaluation)
        );
    }
    // When precompution of prime factor decomposition is done, increase degree
    // in testing
}

#[test]
fn test_degree_with_coeffs() {
    let p = Dense::<Fp, 4, 5>::from_coeffs(vec![
        Fp::from(2_u32),
        Fp::from(3_u32),
        Fp::from(4_u32),
        Fp::from(5_u32),
        Fp::from(6_u32),
        Fp::from(7_u32),
    ]);
    let degree = unsafe { p.degree() };
    assert_eq!(degree, 2);
}

#[test]
fn test_degree_constant() {
    mvpoly::pbt::test_degree_constant::<Fp, 4, 5, Dense<Fp, 4, 5>>();
}

#[test]
fn test_degree_random_degree() {
    mvpoly::pbt::test_degree_random_degree::<Fp, 4, 5, Dense<Fp, 4, 5>>();
    mvpoly::pbt::test_degree_random_degree::<Fp, 1, 20, Dense<Fp, 1, 20>>();
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

    // This might be flaky
    let p = unsafe { Dense::<Fp, 4, 5>::random(&mut rng, None) };
    assert!(!p.is_constant());
}

#[test]
fn test_mvpoly_add_degree_pbt() {
    mvpoly::pbt::test_mvpoly_add_degree_pbt::<Fp, 4, 5, Dense<Fp, 4, 5>>();
}

#[test]
fn test_mvpoly_sub_degree_pbt() {
    mvpoly::pbt::test_mvpoly_sub_degree_pbt::<Fp, 4, 5, Dense<Fp, 4, 5>>();
}

#[test]
fn test_mvpoly_neg_degree_pbt() {
    mvpoly::pbt::test_mvpoly_neg_degree_pbt::<Fp, 4, 5, Dense<Fp, 4, 5>>();
}

#[test]
fn test_mvpoly_mul_by_scalar_degree_pbt() {
    mvpoly::pbt::test_mvpoly_mul_by_scalar_degree_pbt::<Fp, 4, 5, Dense<Fp, 4, 5>>();
}

#[test]
fn test_mvpoly_mul_degree_pbt() {
    mvpoly::pbt::test_mvpoly_mul_degree_pbt::<Fp, 4, 6, Dense<Fp, 4, 6>>();
}

#[test]
fn test_mvpoly_mul_eval_pbt() {
    mvpoly::pbt::test_mvpoly_mul_eval_pbt::<Fp, 4, 6, Dense<Fp, 4, 6>>();
}

#[test]
fn test_mvpoly_mul_pbt() {
    mvpoly::pbt::test_mvpoly_mul_pbt::<Fp, 4, 6, Dense<Fp, 4, 6>>();
}

#[test]
fn test_can_be_printed_with_debug() {
    mvpoly::pbt::test_can_be_printed_with_debug::<Fp, 2, 2, Dense<Fp, 2, 2>>();
}

#[test]
fn test_is_zero() {
    mvpoly::pbt::test_is_zero::<Fp, 4, 6, Dense<Fp, 4, 6>>();
}

#[test]
fn test_homogeneous_eval() {
    let mut rng = o1_utils::tests::make_test_rng(None);
    let random_eval = std::array::from_fn(|_| Fp::rand(&mut rng));
    let u = Fp::rand(&mut rng);
    // Homogeneous form is u^2
    let p1 = Dense::<Fp, 4, 2>::one();
    let homogenous_eval = p1.homogeneous_eval(&random_eval, u);
    assert_eq!(homogenous_eval, u * u);

    let mut p2 = Dense::<Fp, 4, 2>::zero();
    // X1
    p2.add_monomial([1, 0, 0, 0], Fp::one());
    let homogenous_eval = p2.homogeneous_eval(&random_eval, u);
    assert_eq!(homogenous_eval, random_eval[0] * u);

    let mut p3 = Dense::<Fp, 4, 2>::zero();
    // X2
    p3.add_monomial([0, 1, 0, 0], Fp::one());
    let homogenous_eval = p3.homogeneous_eval(&random_eval, u);
    assert_eq!(homogenous_eval, random_eval[1] * u);

    let mut p4 = Dense::<Fp, 4, 2>::zero();
    // X1 * X2
    p4.add_monomial([1, 1, 0, 0], Fp::one());
    let homogenous_eval = p4.homogeneous_eval(&random_eval, u);
    assert_eq!(homogenous_eval, random_eval[0] * random_eval[1]);

    let mut p5 = Dense::<Fp, 4, 2>::zero();
    // X1^2
    p5.add_monomial([2, 0, 0, 0], Fp::one());
    let homogenous_eval = p5.homogeneous_eval(&random_eval, u);
    assert_eq!(homogenous_eval, random_eval[0] * random_eval[0]);

    let mut p6 = Dense::<Fp, 4, 2>::zero();
    // X2^2 + X1^2
    p6.add_monomial([0, 2, 0, 0], Fp::one());
    p6.add_monomial([2, 0, 0, 0], Fp::one());
    let homogenous_eval = p6.homogeneous_eval(&random_eval, u);
    assert_eq!(
        homogenous_eval,
        random_eval[1] * random_eval[1] + random_eval[0] * random_eval[0]
    );

    let mut p7 = Dense::<Fp, 4, 2>::zero();
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
    let mut p1 = Dense::<Fp, 4, 2>::zero();
    p1.add_monomial([0, 0, 0, 0], Fp::one());
    assert_eq!(p1, Dense::<Fp, 4, 2>::one());

    // Adding random constant monomial one to zero
    let mut p2 = Dense::<Fp, 4, 2>::zero();
    let random_c = Fp::rand(&mut rng);
    p2.add_monomial([0, 0, 0, 0], random_c);
    assert_eq!(p2, Dense::<Fp, 4, 2>::from(random_c));

    let mut p3 = Dense::<Fp, 4, 2>::zero();
    let random_c1 = Fp::rand(&mut rng);
    let random_c2 = Fp::rand(&mut rng);
    // X1 + X2
    p3.add_monomial([1, 0, 0, 0], random_c1);
    p3.add_monomial([0, 1, 0, 0], random_c2);

    let random_eval = std::array::from_fn(|_| Fp::rand(&mut rng));
    let eval_p3 = p3.eval(&random_eval);
    let exp_eval_p3 = random_c1 * random_eval[0] + random_c2 * random_eval[1];
    assert_eq!(eval_p3, exp_eval_p3);

    let mut p4 = Dense::<Fp, 4, 2>::zero();
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
fn test_is_multilinear() {
    let mut rng = o1_utils::tests::make_test_rng(None);
    let p1 = Dense::<Fp, 6, 2>::zero();
    assert!(p1.is_multilinear());

    let c = Fp::rand(&mut rng);
    let p2 = Dense::<Fp, 6, 2>::from(c);
    assert!(p2.is_multilinear());

    {
        let mut p = Dense::<Fp, 6, 3>::zero();
        let c = Fp::rand(&mut rng);
        let idx = rng.gen_range(0..6);
        let monomials_exponents = std::array::from_fn(|i| if i == idx { 1 } else { 0 });
        p.add_monomial(monomials_exponents, c);
        assert!(p.is_multilinear());
    }

    {
        let mut p = Dense::<Fp, 6, 4>::zero();
        let c = Fp::rand(&mut rng);
        let nb_var = rng.gen_range(0..4);
        let mut monomials_exponents: [usize; 6] =
            std::array::from_fn(|i| if i <= nb_var { 1 } else { 0 });
        monomials_exponents.shuffle(&mut rng);
        p.add_monomial(monomials_exponents, c);
        assert!(p.is_multilinear());
    }

    // Very unlikely to have a random polynomial being multilinear
    {
        let p = unsafe { Dense::<Fp, 6, 4>::random(&mut rng, None) };
        assert!(!p.is_multilinear());
    }
}
