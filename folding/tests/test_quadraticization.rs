//! quadraticization test, check that diferent cases result in the expected number of columns
//! being added
use ark_poly::Radix2EvaluationDomain;
use folding::{
    expressions::{FoldingColumnTrait, FoldingCompatibleExprInner},
    instance_witness::Foldable,
    Alphas, FoldingCompatibleExpr, FoldingConfig, FoldingEnv, FoldingScheme, Instance, Side,
    Witness,
};
use kimchi::circuits::{expr::Variable, gate::CurrOrNext};
use poly_commitment::srs::SRS;
use std::{
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
};

pub type Fp = ark_bn254::Fr;
pub type Curve = ark_bn254::G1Affine;

#[derive(Hash, Clone, Debug, PartialEq, Eq)]
struct TestConfig;

#[derive(Debug, Clone)]
struct TestInstance;

impl Foldable<Fp> for TestInstance {
    fn combine(_a: Self, _b: Self, _challenge: Fp) -> Self {
        unimplemented!()
    }
}

impl Instance<Curve> for TestInstance {
    fn get_alphas(&self) -> &Alphas<Fp> {
        todo!()
    }

    fn to_absorb(&self) -> (Vec<Fp>, Vec<Curve>) {
        todo!()
    }

    fn get_blinder(&self) -> Fp {
        todo!()
    }
}

#[derive(Clone)]
struct TestWitness;

impl Foldable<Fp> for TestWitness {
    fn combine(_a: Self, _b: Self, _challenge: Fp) -> Self {
        unimplemented!()
    }
}

impl Witness<Curve> for TestWitness {}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
enum Col {
    A,
    B,
}

impl FoldingColumnTrait for Col {
    fn is_witness(&self) -> bool {
        true
    }
}

impl FoldingConfig for TestConfig {
    type Column = Col;

    type Selector = ();

    type Challenge = ();

    type Curve = Curve;

    type Srs = SRS<Curve>;

    type Instance = TestInstance;

    type Witness = TestWitness;

    type Structure = ();

    type Env = Env;
}

struct Env;

impl FoldingEnv<Fp, TestInstance, TestWitness, Col, (), ()> for Env {
    type Structure = ();

    fn new(
        _structure: &Self::Structure,
        _instances: [&TestInstance; 2],
        _witnesses: [&TestWitness; 2],
    ) -> Self {
        todo!()
    }

    fn col(&self, _col: Col, _curr_or_next: CurrOrNext, _side: Side) -> &Vec<Fp> {
        todo!()
    }

    fn challenge(&self, _challenge: (), _side: Side) -> Fp {
        todo!()
    }

    fn selector(&self, _s: &(), _side: Side) -> &Vec<Fp> {
        todo!()
    }
}

fn degree_1_constraint(col: Col) -> FoldingCompatibleExpr<TestConfig> {
    let col = Variable {
        col,
        row: CurrOrNext::Curr,
    };
    FoldingCompatibleExpr::Atom(FoldingCompatibleExprInner::Cell(col))
}

fn degree_n_constraint(n: usize, col: Col) -> FoldingCompatibleExpr<TestConfig> {
    match n {
        0 => {
            panic!("Degree 0 is not supposed to be used by the test suite.")
        }
        // base case
        1 => degree_1_constraint(col),
        _ => {
            let one = degree_1_constraint(col);
            let n_minus_one = degree_n_constraint(n - 1, col);
            FoldingCompatibleExpr::Mul(Box::new(one), Box::new(n_minus_one))
        }
    }
}
// create 2 constraints of degree a and b
fn constraints(a: usize, b: usize) -> Vec<FoldingCompatibleExpr<TestConfig>> {
    vec![
        degree_n_constraint(a, Col::A),
        degree_n_constraint(b, Col::B),
    ]
}
// creates a scheme with the constraints and returns the number of columns added
fn test_with_constraints(constraints: Vec<FoldingCompatibleExpr<TestConfig>>) -> usize {
    use ark_poly::EvaluationDomain;

    let domain = Radix2EvaluationDomain::<Fp>::new(2).unwrap();
    let mut srs = poly_commitment::srs::SRS::<Curve>::create(2);
    srs.add_lagrange_basis(domain);

    let (scheme, _) = FoldingScheme::<TestConfig>::new(constraints, &srs, domain, &());
    // println!("exp:\n {}", exp.to_string());
    scheme.get_number_of_additional_columns()
}

// 1 constraint of degree 1
#[test]
fn quadraticization_test_1() {
    let mut constraints = constraints(1, 1);
    constraints.truncate(1);
    assert_eq!(test_with_constraints(constraints), 0);
}

// 1 constraint of degree 2
#[test]
fn quadraticization_test_2() {
    let mut constraints = constraints(2, 1);
    constraints.truncate(1);
    assert_eq!(test_with_constraints(constraints), 0);
}

// 1 constraint of degree 3
#[test]
fn quadraticization_test_3() {
    let mut constraints = constraints(3, 1);
    constraints.truncate(1);
    assert_eq!(test_with_constraints(constraints), 1);
}

// 1 constraint of degree 4 to 8 (as we usually support up to 8).
#[test]
fn quadraticization_test_4() {
    let cols = [2, 3, 4, 5, 6];
    for i in 4..=8 {
        let mut constraints = constraints(i, 1);
        constraints.truncate(1);
        assert_eq!(test_with_constraints(constraints), cols[i - 4]);
    }
}

// 2 constraints of degree 1
#[test]
fn quadraticization_test_5() {
    let constraints = constraints(1, 1);
    assert_eq!(test_with_constraints(constraints), 0);
}

// 2 constraints, one of degree 1 and one of degree 2
#[test]
fn quadraticization_test_6() {
    let constraints = constraints(1, 2);
    assert_eq!(test_with_constraints(constraints), 0);
}

// 2 constraints: one of degree 1 and one of degree 3
#[test]
fn quadraticization_test_7() {
    let constraints = constraints(1, 3);
    assert_eq!(test_with_constraints(constraints), 1);
}

// 2 constraints, each with degree higher than 2.
#[test]
fn quadraticization_test_8() {
    let constraints = constraints(4, 3);
    assert_eq!(test_with_constraints(constraints), 3);
}

// shared subexpression
#[test]
fn quadraticization_test_9() {
    // here I duplicate the first constraint
    let mut constraints = constraints(3, 1);
    constraints.truncate(1);
    constraints.push(constraints[0].clone());
    assert_eq!(test_with_constraints(constraints), 1);
}

#[test]
fn test_equality_folding_compatible_expressions() {
    let x: FoldingCompatibleExpr<TestConfig> =
        FoldingCompatibleExpr::Atom(FoldingCompatibleExprInner::Cell(Variable {
            col: Col::A,
            row: CurrOrNext::Curr,
        }));
    let y = FoldingCompatibleExpr::Atom(FoldingCompatibleExprInner::Cell(Variable {
        col: Col::A,
        row: CurrOrNext::Curr,
    }));

    let z = FoldingCompatibleExpr::Atom(FoldingCompatibleExprInner::Cell(Variable {
        col: Col::B,
        row: CurrOrNext::Curr,
    }));

    assert_eq!(x, y);
    assert_eq!(x, x);
    assert_ne!(x, z);
}

#[test]
fn test_discriminant_folding_expressions() {
    let x: FoldingCompatibleExpr<TestConfig> =
        FoldingCompatibleExpr::Atom(FoldingCompatibleExprInner::Cell(Variable {
            col: Col::A,
            row: CurrOrNext::Curr,
        }));
    let y: FoldingCompatibleExpr<TestConfig> =
        FoldingCompatibleExpr::Atom(FoldingCompatibleExprInner::Cell(Variable {
            col: Col::A,
            row: CurrOrNext::Curr,
        }));

    let z: FoldingCompatibleExpr<TestConfig> =
        FoldingCompatibleExpr::Atom(FoldingCompatibleExprInner::Cell(Variable {
            col: Col::B,
            row: CurrOrNext::Curr,
        }));

    let x = x.simplify();
    let y = y.simplify();
    let z = z.simplify();

    let x_hasher = {
        let mut x_hasher = DefaultHasher::new();
        x.hash(&mut x_hasher);
        x_hasher.finish()
    };

    // Checking hashing the same element twice give the same result
    {
        let x_prime_hasher = {
            let mut x_hasher = DefaultHasher::new();
            x.hash(&mut x_hasher);
            x_hasher.finish()
        };
        assert_eq!(x_hasher, x_prime_hasher);
    }

    let y_hasher = {
        let mut y_hasher = DefaultHasher::new();
        y.hash(&mut y_hasher);
        y_hasher.finish()
    };

    let z_hasher = {
        let mut z_hasher = DefaultHasher::new();
        z.hash(&mut z_hasher);
        z_hasher.finish()
    };

    {
        let (y_hasher, z_hasher) = {
            let mut hasher = DefaultHasher::new();
            y.hash(&mut hasher);
            let y_hasher = hasher.finish();

            z.hash(&mut hasher);
            (y_hasher, hasher.finish())
        };
        assert_ne!(y_hasher, z_hasher);
    }

    assert_eq!(x_hasher, x_hasher);
    assert_eq!(x_hasher, y_hasher);
    assert_ne!(x_hasher, z_hasher);
}
