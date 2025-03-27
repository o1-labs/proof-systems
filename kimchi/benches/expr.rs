use criterion::{criterion_group, criterion_main, Criterion};
use kimchi::linearization::constraints_expr;
use std::collections::HashMap;
use std::{hint::black_box, ops::Index};

use ark_ff::{FftField, UniformRand, Zero};
use ark_poly::{EvaluationDomain, Evaluations, Radix2EvaluationDomain as D};
use kimchi::circuits::berkeley_columns::{witness_curr, BerkeleyChallenges, Environment, E};
use kimchi::circuits::domains::EvaluationDomains;
use kimchi::circuits::expr::{l0_1, ColumnEnvironment, ConstantExpr, Constants, Expr};
use kimchi::curve::KimchiCurve;
use mina_curves::pasta::{Fp, Pallas, Vesta};
use rand::rngs::StdRng;
use rand::{random, Rng};

fn evaluate_simple<
    'a,
    Challenge: Index<ChallengeTerm, Output = F>,
    Environment: ColumnEnvironment<'a, F, ChallengeTerm, Challenge, Column = Column>,
    F: FftField,
    Column: PartialEq + Copy,
    ChallengeTerm: Copy,
>(
    e: Expr<ConstantExpr<F, ChallengeTerm>, Column>,
    env: &Environment,
) -> Evaluations<F, D<F>> {
    e.evaluations(env)
}

fn create_random_evaluation(domain: D<Fp>, rng: &mut impl Rng) -> Evaluations<Fp, D<Fp>> {
    let evals = (0..domain.size)
        .map(|_| Fp::rand(rng))
        .collect::<Vec<_>>()
        .into();
    Evaluations::from_vec_and_domain(evals, domain)
}

fn benchmark_expr_evaluations(c: &mut Criterion) {
    // We use d1!
    // FIXME: Fix log_domain_size = 16
    let domains = EvaluationDomains::<Fp>::create(1 << 16).unwrap();
    let domain = domains.d8;
    let mut rng = rand::thread_rng();
    // FIXME: Use const
    // FIXME: Dedup
    let randomized_witness = (0..15)
        .map(|_| create_random_evaluation(domain, &mut rng))
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    let randomized_coefficients = (0..15)
        .map(|_| create_random_evaluation(domain, &mut rng))
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    let randomized_vanishes_on_zero_knowledge_and_previous_rows =
        create_random_evaluation(domain, &mut rng);
    let randomized_z = create_random_evaluation(domain, &mut rng);
    let randomized_l0_1 = Fp::rand(&mut rng);
    let constants = Constants {
        endo_coefficient: Fp::rand(&mut rng),
        mds: &Vesta::sponge_params().mds,
        zk_rows: 0,
    };
    let challenges = BerkeleyChallenges {
        alpha: Fp::rand(&mut rng),
        beta: Fp::rand(&mut rng),
        gamma: Fp::rand(&mut rng),
        joint_combiner: Fp::rand(&mut rng),
    };

    let env = Environment {
        witness: &randomized_witness,
        coefficient: &randomized_coefficients,
        vanishes_on_zero_knowledge_and_previous_rows:
            &randomized_vanishes_on_zero_knowledge_and_previous_rows,
        z: &randomized_z,
        index: HashMap::new(),
        l0_1: randomized_l0_1,
        constants,
        challenges,
        domain: domains,
        lookup: None,
    };

    let expr: E<Fp> = constraints_expr(None, true).0;

    c.bench_function("expr_evals_vec", |b| {
        b.iter(|| evaluate_simple(black_box(expr.clone()), black_box(&env)).evals.iter().for_each(|x| println!("{:?}", x)))
    });
}

fn benchmark_expr_evaluations_iter(c: &mut Criterion) {
    // We use d1!
    // FIXME: Fix log_domain_size = 16
    let domains = EvaluationDomains::<Fp>::create(1 << 16).unwrap();
    let domain = domains.d8;
    let mut rng = rand::thread_rng();
    // FIXME: Use const
    // FIXME: Dedup
    let randomized_witness = (0..15)
        .map(|_| create_random_evaluation(domain, &mut rng))
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    let randomized_coefficients = (0..15)
        .map(|_| create_random_evaluation(domain, &mut rng))
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    let randomized_vanishes_on_zero_knowledge_and_previous_rows =
        create_random_evaluation(domain, &mut rng);
    let randomized_z = create_random_evaluation(domain, &mut rng);
    let randomized_l0_1 = Fp::rand(&mut rng);
    let constants = Constants {
        endo_coefficient: Fp::rand(&mut rng),
        mds: &Vesta::sponge_params().mds,
        zk_rows: 0,
    };
    let challenges = BerkeleyChallenges {
        alpha: Fp::rand(&mut rng),
        beta: Fp::rand(&mut rng),
        gamma: Fp::rand(&mut rng),
        joint_combiner: Fp::rand(&mut rng),
    };

    let env = Environment {
        witness: &randomized_witness,
        coefficient: &randomized_coefficients,
        vanishes_on_zero_knowledge_and_previous_rows:
            &randomized_vanishes_on_zero_knowledge_and_previous_rows,
        z: &randomized_z,
        index: HashMap::new(),
        l0_1: randomized_l0_1,
        constants,
        challenges,
        domain: domains,
        lookup: None,
    };

    let expr: E<Fp> = constraints_expr(None, true).0;

    c.bench_function("expr_evals_iter", |b| {
        b.iter(|| for eval in black_box(expr.evaluations_iter(black_box(env.clone()))) { black_box(println!("{:?}", eval)); })
    });
}


criterion_group!(evaluation_bench,
    //benchmark_expr_evaluations,
    benchmark_expr_evaluations_iter);
criterion_main!(evaluation_bench);
