use ark_ff::{One, UniformRand, Zero};
use kimchi::circuits::{
    berkeley_columns::BerkeleyChallengeTerm,
    expr::{ConstantExpr, Expr, ExprInner, Variable},
    gate::CurrOrNext,
};
use mina_curves::pasta::Fp;
use mvpoly::{prime::Dense, utils::PrimeNumberGenerator, MVPoly};
use rand::Rng;

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

    let p = Dense::<Fp, 4, 5>::from_variable::<Column>(
        Variable {
            col: Column::X(0),
            row: CurrOrNext::Curr,
        },
        None,
    );
    assert_eq!(p[0], Fp::zero());
    assert_eq!(p[1], Fp::one());
    assert_eq!(p[2], Fp::zero());
    assert_eq!(p[3], Fp::zero());
    assert_eq!(p[4], Fp::zero());
    assert_eq!(p[5], Fp::zero());

    // Test for z variable (index 3)
    let p = Dense::<Fp, 4, 5>::from_variable::<Column>(
        Variable {
            col: Column::X(1),
            row: CurrOrNext::Curr,
        },
        None,
    );
    assert_eq!(p[0], Fp::zero());
    assert_eq!(p[1], Fp::zero());
    assert_eq!(p[2], Fp::one());
    assert_eq!(p[3], Fp::zero());
    assert_eq!(p[4], Fp::zero());

    // Test for w variable (index 5)
    let p = Dense::<Fp, 4, 5>::from_variable::<Column>(
        Variable {
            col: Column::X(2),
            row: CurrOrNext::Curr,
        },
        None,
    );
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
    // o1vm/arrabbiata
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

        let p = Dense::<Fp, 7, 2>::from_expr::<Column, BerkeleyChallengeTerm>(expression, None);
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
        let p = Dense::<Fp, 7, 2>::from_expr::<Column, BerkeleyChallengeTerm>(expr, None);
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
        let p = Dense::<Fp, 7, 2>::from_expr::<Column, BerkeleyChallengeTerm>(expr, None);
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
    mvpoly::pbt::test_degree_random_degree::<Fp, 1, 7, Dense<Fp, 1, 7>>();
}

#[test]
fn test_is_constant() {
    mvpoly::pbt::test_is_constant::<Fp, 4, 5, Dense<Fp, 4, 5>>();
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
    mvpoly::pbt::test_homogeneous_eval::<Fp, 4, 2, Dense<Fp, 4, 2>>();
}

#[test]
fn test_add_monomial() {
    mvpoly::pbt::test_add_monomial::<Fp, 4, 2, Dense<Fp, 4, 2>>();
}

#[test]
fn test_is_multilinear() {
    mvpoly::pbt::test_is_multilinear::<Fp, 6, 2, Dense<Fp, 6, 2>>();
}

#[test]
#[should_panic]
fn test_build_from_variable_next_row_without_offset_given() {
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

    let mut rng = o1_utils::tests::make_test_rng(None);
    let idx: usize = rng.gen_range(0..4);
    let _p = Dense::<Fp, 4, 3>::from_variable::<Column>(
        Variable {
            col: Column::X(idx),
            row: CurrOrNext::Next,
        },
        None,
    );
}

#[test]
fn test_build_from_variable_next_row_with_offset_given() {
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

    let mut rng = o1_utils::tests::make_test_rng(None);
    let idx: usize = rng.gen_range(0..4);

    // Using next
    {
        let p = Dense::<Fp, 8, 3>::from_variable::<Column>(
            Variable {
                col: Column::X(idx),
                row: CurrOrNext::Next,
            },
            Some(4),
        );

        let eval: [Fp; 8] = std::array::from_fn(|_i| Fp::rand(&mut rng));
        assert_eq!(p.eval(&eval), eval[idx + 4]);
    }

    // Still using current
    {
        let p = Dense::<Fp, 8, 3>::from_variable::<Column>(
            Variable {
                col: Column::X(idx),
                row: CurrOrNext::Curr,
            },
            Some(4),
        );

        let eval: [Fp; 8] = std::array::from_fn(|_i| Fp::rand(&mut rng));
        assert_eq!(p.eval(&eval), eval[idx]);
    }
}
