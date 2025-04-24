use ark_ff::{One, UniformRand, Zero};
use kimchi::circuits::{
    berkeley_columns::BerkeleyChallengeTerm,
    expr::{ConstantExpr, Expr, ExprInner, Variable},
    gate::CurrOrNext,
};
use mina_curves::pasta::Fp;
use mvpoly::{monomials::Sparse, MVPoly};
use std::time::Instant;

fn bench_sparse_cross_terms_computation_scaled() {
    let mut rng = o1_utils::tests::make_test_rng(None);
    let p1: Sparse<Fp, 10, 7> = unsafe { Sparse::random(&mut rng, None) };
    let eval_left: [Fp; 10] = std::array::from_fn(|_| Fp::rand(&mut rng));
    let eval_right: [Fp; 10] = std::array::from_fn(|_| Fp::rand(&mut rng));
    let u1 = Fp::rand(&mut rng);
    let u2 = Fp::rand(&mut rng);
    let a1 = Fp::rand(&mut rng);
    let a2 = Fp::rand(&mut rng);
    let start_timer = Instant::now();
    p1.compute_cross_terms_scaled(&eval_left, &eval_right, u1, u2, a1, a2);
    let elapsed = start_timer.elapsed();
    println!("sparse cross terms computation scaled: {:?}", elapsed);
}

fn bench_sparse_cross_terms_computation_ec_addition() {
    // Simulate a real usecase of the sparse cross terms computation
    // The bench is related to a case we mightencounter in the context of
    // Arrabbiata, i.e. a setup with 15 private columns, 15 public inputs, and
    // 15 columns for the "next row".
    // The following lines/design look similar to the ones we use in
    // o1vm/arrabbiata
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
    // - Constraint 1: λ (X1 - X2) - Y1 + Y2 = 0
    let p1 = {
        let expr = lambda.clone() * (x1.clone() - x2.clone()) - (y1.clone() - y2.clone());
        Sparse::<Fp, 7, 2>::from_expr::<Column, BerkeleyChallengeTerm>(expr, None)
    };

    // - Constraint 2: X3 + X1 + X2 - λ^2 = 0
    let p2 = {
        let expr = x3.clone() + x1.clone() + x2.clone() - lambda.clone() * lambda.clone();
        Sparse::<Fp, 7, 2>::from_expr::<Column, BerkeleyChallengeTerm>(expr, None)
    };

    // - Constraint 3: Y3 - λ (X1 - X3) + Y1 = 0
    let p3 = {
        let expr = y3.clone() - lambda.clone() * (x1.clone() - x3.clone()) + y1.clone();
        Sparse::<Fp, 7, 2>::from_expr::<Column, BerkeleyChallengeTerm>(expr, None)
    };

    let circuits = [p1, p2, p3];
    // - simulate the evaluation of the circuits, and increase artificially the degree to 5.
    // - add some public values, i.e. random columns.
    // - Add 8 random columns, plus 15 public inputs + another 15 columns for
    // the "next row".
    // - Only the first 8 columns are filled with random values
    // for the eval right.
    // - For the eval left, we have random values for everything.
    let circuits: Vec<Sparse<Fp, 7, 5>> = circuits
        .into_iter()
        .map(|c| {
            let res: Result<Sparse<Fp, 7, 5>, _> = c.into();
            res.unwrap()
        })
        .collect();
    let circuits: Vec<Sparse<Fp, 45, 5>> = circuits
        .into_iter()
        .map(|c| {
            let res: Result<Sparse<Fp, 45, 5>, _> = c.into();
            res.unwrap()
        })
        .collect();

    let mut rng = o1_utils::tests::make_test_rng(None);
    let eval_left: [Fp; 45] = std::array::from_fn(|_| Fp::rand(&mut rng));
    let eval_right: [Fp; 45] = std::array::from_fn(|i| {
        if i < 7 {
            Fp::rand(&mut rng)
        } else {
            Fp::zero()
        }
    });
    let u1 = Fp::rand(&mut rng);
    // The right u is always one as we suppose the constraints are not
    // "relaxed".
    let u2 = Fp::one();
    let combiner1 = Fp::rand(&mut rng);
    let combiner2 = Fp::rand(&mut rng);

    let start_timer = Instant::now();
    let res = mvpoly::compute_combined_cross_terms(
        circuits, eval_left, eval_right, u1, u2, combiner1, combiner2,
    );
    let elapsed = start_timer.elapsed();
    // Only printing to be sure that the compiler does not optimize the code and
    // remove the computation.
    // We know how compilers can be annoying sometimes.
    println!("res: {:?}", res);
    println!("Sparse cross terms computation ec addition: {:?}", elapsed);
}

fn main() {
    bench_sparse_cross_terms_computation_scaled();
    bench_sparse_cross_terms_computation_ec_addition();
}
