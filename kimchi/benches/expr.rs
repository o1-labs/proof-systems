use criterion::{criterion_group, criterion_main, Criterion};
use kimchi::linearization::constraints_expr;
use std::{collections::HashMap, hint::black_box};

use ark_ff::UniformRand;
use ark_poly::{Evaluations, Radix2EvaluationDomain as D};
use kimchi::{
    circuits::{
        berkeley_columns::{BerkeleyChallenges, Environment, E},
        domains::EvaluationDomains,
        expr::Constants,
    },
    curve::KimchiCurve,
};
use mina_curves::pasta::{Fp, Vesta};
use rand::Rng;

fn create_random_evaluation(domain: D<Fp>, rng: &mut impl Rng) -> Evaluations<Fp, D<Fp>> {
    let evals = (0..domain.size).map(|_| Fp::rand(rng)).collect::<Vec<_>>();
    Evaluations::from_vec_and_domain(evals, domain)
}

fn benchmark_expr_evaluations(c: &mut Criterion) {
    let domains = EvaluationDomains::<Fp>::create(1 << 16).unwrap();
    let domain = domains.d8;
    let mut rng = rand::thread_rng();
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

    c.bench_function("expr_evals_par", |b| {
        b.iter(|| black_box(expr.clone()).evaluations(black_box(&env)));
    });
}

criterion_group!(
    name = evaluation_bench_seq;
    config = Criterion::default().sample_size(10);
    targets = benchmark_expr_evaluations
);

criterion_main!(evaluation_bench_seq);
