/// Tests for the proof system itself, targeting prover and verifier.
#[cfg(test)]
mod tests {

    use crate::{
        columns::Column,
        expr::{
            E, {self},
        },
        test::test_completeness_generic_only_relation,
        witness::Witness,
        Fp,
    };
    use ark_ff::{Field, One, UniformRand};
    use kimchi::circuits::expr::{ConstantExpr, ConstantTerm};

    // Test a constraint of degree one: X_{0} - X_{1}
    #[test]
    fn test_completeness_degree_one() {
        let mut rng = o1_utils::tests::make_test_rng(None);
        const N: usize = 2;
        let domain_size = 1 << 8;

        let constraints = {
            let x0 = expr::curr_cell::<Fp>(Column::Relation(0));
            let x1 = expr::curr_cell::<Fp>(Column::Relation(1));
            vec![x0.clone() - x1]
        };

        let random_x0s: Vec<Fp> = (0..domain_size).map(|_| Fp::rand(&mut rng)).collect();
        let exp_x1 = random_x0s.clone();
        let witness: Witness<N, Vec<Fp>> = Witness {
            cols: Box::new([random_x0s, exp_x1]),
        };

        test_completeness_generic_only_relation::<N, _>(
            constraints.clone(),
            witness.clone(),
            domain_size,
            &mut rng,
        );
        // FIXME: we would want to allow the prover to make a proof, but the verification must fail.
        // TODO: Refactorize code in prover to handle a degug or add an adversarial prover.
        // test_soundness_generic(constraints, witness, domain_size, &mut rng);
    }

    // Test a constraint of degree two: X_{0} * X_{0} - X_{1} - X_{2}
    #[test]
    fn test_completeness_degree_two() {
        let mut rng = o1_utils::tests::make_test_rng(None);
        const N: usize = 3;
        let domain_size = 1 << 8;

        let constraints = {
            let x0 = expr::curr_cell::<Fp>(Column::Relation(0));
            let x1 = expr::curr_cell::<Fp>(Column::Relation(1));
            let x2 = expr::curr_cell::<Fp>(Column::Relation(2));
            vec![x0.clone() * x0.clone() - x1.clone() - x2.clone()]
        };

        let random_x0s: Vec<Fp> = (0..domain_size).map(|_| Fp::rand(&mut rng)).collect();
        let random_x1s: Vec<Fp> = (0..domain_size).map(|_| Fp::rand(&mut rng)).collect();
        let exp_x2 = random_x0s
            .iter()
            .zip(random_x1s.iter())
            .map(|(x0, x1)| (*x0) * (*x0) - x1)
            .collect::<Vec<Fp>>();
        let witness: Witness<N, Vec<Fp>> = Witness {
            cols: Box::new([random_x0s, random_x1s, exp_x2]),
        };

        test_completeness_generic_only_relation::<N, _>(
            constraints.clone(),
            witness.clone(),
            domain_size,
            &mut rng,
        );
        // FIXME: we would want to allow the prover to make a proof, but the verification must fail.
        // TODO: Refactorize code in prover to handle a degug or add an adversarial prover.
        // test_soundness_generic(constraints, witness, domain_size, &mut rng);
    }

    // Test a constraint of degree three:
    //   X_{0} * X_{0} * X_{0} \
    // - 42 * X_{1} * X_{2} \
    // + X_{3}
    #[test]
    fn test_completeness_degree_three() {
        let mut rng = o1_utils::tests::make_test_rng(None);
        const N: usize = 4;
        let domain_size = 1 << 8;

        let constraints = {
            let x0 = expr::curr_cell::<Fp>(Column::Relation(0));
            let x1 = expr::curr_cell::<Fp>(Column::Relation(1));
            let x2 = expr::curr_cell::<Fp>(Column::Relation(2));
            let x3 = expr::curr_cell::<Fp>(Column::Relation(3));
            vec![
                x0.clone() * x0.clone() * x0.clone() - E::from(42) * x1.clone() * x2.clone()
                    + x3.clone(),
            ]
        };

        let random_x0s: Vec<Fp> = (0..domain_size).map(|_| Fp::rand(&mut rng)).collect();
        let random_x1s: Vec<Fp> = (0..domain_size).map(|_| Fp::rand(&mut rng)).collect();
        let random_x2s: Vec<Fp> = (0..domain_size).map(|_| Fp::rand(&mut rng)).collect();
        let exp_x3 = random_x0s
            .iter()
            .zip(random_x1s.iter())
            .zip(random_x2s.iter())
            .map(|((x0, x1), x2)| -((*x0) * (*x0) * (*x0) - Fp::from(42) * (*x1) * (*x2)))
            .collect::<Vec<Fp>>();
        let witness: Witness<N, Vec<Fp>> = Witness {
            cols: Box::new([random_x0s, random_x1s, random_x2s, exp_x3]),
        };

        test_completeness_generic_only_relation::<N, _>(
            constraints.clone(),
            witness.clone(),
            domain_size,
            &mut rng,
        );
        // FIXME: we would want to allow the prover to make a proof, but the verification must fail.
        // TODO: Refactorize code in prover to handle a degug or add an adversarial prover.
        // test_soundness_generic(constraints, witness, domain_size, &mut rng);
    }

    #[test]
    // X_{0} * (X_{1} * X_{2} * X_{3} + 1)
    fn test_completeness_degree_four() {
        let mut rng = o1_utils::tests::make_test_rng(None);
        const N: usize = 4;
        let domain_size = 1 << 8;

        let constraints = {
            let x0 = expr::curr_cell::<Fp>(Column::Relation(0));
            let x1 = expr::curr_cell::<Fp>(Column::Relation(1));
            let x2 = expr::curr_cell::<Fp>(Column::Relation(2));
            let x3 = expr::curr_cell::<Fp>(Column::Relation(3));
            let one = ConstantExpr::from(ConstantTerm::Literal(Fp::one()));
            vec![x0.clone() * (x1.clone() * x2.clone() * x3.clone() + E::constant(one))]
        };

        let random_x0s: Vec<Fp> = (0..domain_size).map(|_| Fp::rand(&mut rng)).collect();
        let random_x1s: Vec<Fp> = (0..domain_size).map(|_| Fp::rand(&mut rng)).collect();
        let random_x2s: Vec<Fp> = (0..domain_size).map(|_| Fp::rand(&mut rng)).collect();
        let exp_x3 = random_x1s
            .iter()
            .zip(random_x2s.iter())
            .map(|(x1, x2)| -Fp::one() / (*x1 * *x2))
            .collect::<Vec<Fp>>();
        let witness: Witness<N, Vec<Fp>> = Witness {
            cols: Box::new([random_x0s, random_x1s, random_x2s, exp_x3]),
        };

        test_completeness_generic_only_relation::<N, _>(
            constraints.clone(),
            witness.clone(),
            domain_size,
            &mut rng,
        );
        // FIXME: we would want to allow the prover to make a proof, but the verification must fail.
        // TODO: Refactorize code in prover to handle a degug or add an adversarial prover.
        // test_soundness_generic(constraints, witness, domain_size, &mut rng);
    }

    #[test]
    // X_{0}^5 + X_{1}
    fn test_completeness_degree_five() {
        let mut rng = o1_utils::tests::make_test_rng(None);
        const N: usize = 2;
        let domain_size = 1 << 8;

        let constraints = {
            let x0 = expr::curr_cell::<Fp>(Column::Relation(0));
            let x1 = expr::curr_cell::<Fp>(Column::Relation(1));
            vec![x0.clone() * x0.clone() * x0.clone() * x0.clone() * x0.clone() + x1.clone()]
        };

        let random_x0s: Vec<Fp> = (0..domain_size).map(|_| Fp::rand(&mut rng)).collect();
        let exp_x1 = random_x0s
            .iter()
            .map(|x0| -*x0 * *x0 * *x0 * *x0 * *x0)
            .collect::<Vec<Fp>>();
        let witness: Witness<N, Vec<Fp>> = Witness {
            cols: Box::new([random_x0s, exp_x1]),
        };

        test_completeness_generic_only_relation::<N, _>(
            constraints.clone(),
            witness.clone(),
            domain_size,
            &mut rng,
        );
        // FIXME: we would want to allow the prover to make a proof, but the verification must fail.
        // TODO: Refactorize code in prover to handle a degug or add an adversarial prover.
        // test_soundness_generic(constraints, witness, domain_size, &mut rng);
    }

    #[test]
    // X_{0}^3 + X_{1} AND X_{2}^2 - 3 X_{3}
    fn test_completeness_different_constraints_different_degrees() {
        let mut rng = o1_utils::tests::make_test_rng(None);
        const N: usize = 4;
        let domain_size = 1 << 8;

        let constraints = {
            let x0 = expr::curr_cell::<Fp>(Column::Relation(0));
            let x1 = expr::curr_cell::<Fp>(Column::Relation(1));
            let cst1 = x0.clone() * x0.clone() * x0.clone() + x1.clone();
            let x2 = expr::curr_cell::<Fp>(Column::Relation(2));
            let x3 = expr::curr_cell::<Fp>(Column::Relation(3));
            let three = ConstantExpr::from(ConstantTerm::Literal(Fp::from(3)));
            let cst2 = x2.clone() * x2.clone() - E::constant(three) * x3.clone();
            vec![cst1, cst2]
        };

        let random_x0s: Vec<Fp> = (0..domain_size).map(|_| Fp::rand(&mut rng)).collect();
        let exp_x1 = random_x0s
            .iter()
            .map(|x0| -*x0 * *x0 * *x0)
            .collect::<Vec<Fp>>();
        let random_x2s: Vec<Fp> = (0..domain_size).map(|_| Fp::rand(&mut rng)).collect();
        let exp_x3: Vec<Fp> = random_x2s
            .iter()
            .map(|x2| (Fp::one() / Fp::from(3)) * x2 * x2)
            .collect::<Vec<Fp>>();
        let witness: Witness<N, Vec<Fp>> = Witness {
            cols: Box::new([random_x0s, exp_x1, random_x2s, exp_x3]),
        };

        test_completeness_generic_only_relation::<N, _>(
            constraints.clone(),
            witness.clone(),
            domain_size,
            &mut rng,
        );
        // FIXME: we would want to allow the prover to make a proof, but the verification must fail.
        // TODO: Refactorize code in prover to handle a degug or add an adversarial prover.
        // test_soundness_generic(constraints, witness, domain_size, &mut rng);
    }

    #[test]
    // X_{0}^6 + X_{1}^4 - X_{2}^3 - 2 X_{3}
    fn test_completeness_degree_six() {
        let mut rng = o1_utils::tests::make_test_rng(None);
        const N: usize = 4;
        let domain_size = 1 << 8;

        let constraints = {
            let x0 = expr::curr_cell::<Fp>(Column::Relation(0));
            let x1 = expr::curr_cell::<Fp>(Column::Relation(1));
            let x2 = expr::curr_cell::<Fp>(Column::Relation(2));
            let x3 = expr::curr_cell::<Fp>(Column::Relation(3));
            let x0_square = x0.clone() * x0.clone();
            let x1_square = x1.clone() * x1.clone();
            let x2_square = x2.clone() * x2.clone();
            let two = ConstantExpr::from(ConstantTerm::Literal(Fp::from(2)));
            vec![
                x0_square.clone() * x0_square.clone() * x0_square.clone()
                    + x1_square.clone() * x1_square.clone()
                    - x2_square.clone() * x2.clone()
                    - E::constant(two) * x3.clone(),
            ]
        };

        let random_x0s: Vec<Fp> = (0..domain_size).map(|_| Fp::rand(&mut rng)).collect();
        let random_x1s: Vec<Fp> = (0..domain_size).map(|_| Fp::rand(&mut rng)).collect();
        let random_x2s: Vec<Fp> = (0..domain_size).map(|_| Fp::rand(&mut rng)).collect();
        let exp_x3 = random_x0s
            .iter()
            .zip(random_x1s.iter())
            .zip(random_x2s.iter())
            .map(|((x0, x1), x2)| {
                let x0_square = x0.clone().square();
                let x1_square = x1.clone().square();
                let x2_square = x2.clone().square();
                let x0_six = x0_square * x0_square * x0_square;
                let x1_four = x1_square * x1_square;
                (Fp::one() / Fp::from(2)) * (x0_six + x1_four - x2_square * x2)
            })
            .collect::<Vec<Fp>>();
        let witness: Witness<N, Vec<Fp>> = Witness {
            cols: Box::new([random_x0s, random_x1s, random_x2s, exp_x3]),
        };

        test_completeness_generic_only_relation::<N, _>(
            constraints.clone(),
            witness.clone(),
            domain_size,
            &mut rng,
        );
        // FIXME: we would want to allow the prover to make a proof, but the verification must fail.
        // TODO: Refactorize code in prover to handle a degug or add an adversarial prover.
        // test_soundness_generic(constraints, witness, domain_size, &mut rng);
    }

    #[test]
    // X_{0}^7 + X_{1}^4 - X_{2}^3 - 2 X_{3}
    fn test_completeness_degree_seven() {
        let mut rng = o1_utils::tests::make_test_rng(None);
        const N: usize = 4;
        let domain_size = 1 << 8;

        let constraints = {
            let x0 = expr::curr_cell::<Fp>(Column::Relation(0));
            let x1 = expr::curr_cell::<Fp>(Column::Relation(1));
            let x2 = expr::curr_cell::<Fp>(Column::Relation(2));
            let x3 = expr::curr_cell::<Fp>(Column::Relation(3));
            let x0_square = x0.clone() * x0.clone();
            let x1_square = x1.clone() * x1.clone();
            let x2_square = x2.clone() * x2.clone();
            let two = ConstantExpr::from(ConstantTerm::Literal(Fp::from(2)));
            vec![
                x0_square.clone() * x0_square.clone() * x0_square.clone() * x0.clone()
                    + x1_square.clone() * x1_square.clone()
                    - x2_square.clone() * x2.clone()
                    - E::constant(two) * x3.clone(),
            ]
        };

        let random_x0s: Vec<Fp> = (0..domain_size).map(|_| Fp::rand(&mut rng)).collect();
        let random_x1s: Vec<Fp> = (0..domain_size).map(|_| Fp::rand(&mut rng)).collect();
        let random_x2s: Vec<Fp> = (0..domain_size).map(|_| Fp::rand(&mut rng)).collect();
        let exp_x3 = random_x0s
            .iter()
            .zip(random_x1s.iter())
            .zip(random_x2s.iter())
            .map(|((x0, x1), x2)| {
                let x0_square = x0.clone().square();
                let x1_square = x1.clone().square();
                let x2_square = x2.clone().square();
                let x0_six = x0_square * x0_square * x0_square * x0;
                let x1_four = x1_square * x1_square;
                (Fp::one() / Fp::from(2)) * (x0_six + x1_four - x2_square * x2)
            })
            .collect::<Vec<Fp>>();
        let witness: Witness<N, Vec<Fp>> = Witness {
            cols: Box::new([random_x0s, random_x1s, random_x2s, exp_x3]),
        };

        test_completeness_generic_only_relation::<N, _>(
            constraints.clone(),
            witness.clone(),
            domain_size,
            &mut rng,
        );
        // FIXME: we would want to allow the prover to make a proof, but the verification must fail.
        // TODO: Refactorize code in prover to handle a degug or add an adversarial prover.
        // test_soundness_generic(constraints, witness, domain_size, &mut rng);
    }
}
