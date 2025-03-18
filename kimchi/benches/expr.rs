use std::{hint::black_box, ops::Index};
use criterion::{criterion_group, criterion_main, Criterion};

use ark_ff::{FftField, Zero};
use ark_poly::{Evaluations, Radix2EvaluationDomain as D};
use kimchi::circuits::expr::{ColumnEnvironment, ConstantExpr, Expr};
use kimchi::circuits::berkeley_columns::{witness_curr, E};
use mina_curves::pasta::Fp;

fn evaluate_simple<
    'a,
    Challenge: Index<ChallengeTerm, Output = F>,
    Environment: ColumnEnvironment<'a, F, ChallengeTerm, Challenge, Column = Column>,
    F: FftField,
    Column: PartialEq + Copy,
    ChallengeTerm: Copy
>(
    e: Expr<ConstantExpr<F, ChallengeTerm>, Column>,
    env: &Environment
) -> Evaluations<F, D<F>> {
    e.evaluations(env)
}

fn benchmark_expr_evaluations(c: &mut Criterion) {
    let env = todo!();
    let mut expr : E<Fp> = E::zero();
    // (X0 + 100 * X1) * X3 ^ 3
    expr += witness_curr(0);
    expr += 100u64.into() * witness_curr(1);
    expr *= witness_curr(2).pow(3);

    c.bench_function("fib 20", |b| b.iter(|| evaluate_simple(black_box(expr), black_box(&env))));
}

criterion_group!(evaluation_bench, benchmark_expr_evaluations);
criterion_main!(evaluation_bench);