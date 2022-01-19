use criterion::{criterion_group, criterion_main, Criterion};
use kimchi::bench::{BenchmarkCtx, GATES};
use std::time::Duration;

pub fn bench_proof_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("Proof creation");
    group
        .measurement_time(Duration::from_secs(200))
        .sample_size(10);

    let num_gates = (GATES as f64).log2();

    let ctx = BenchmarkCtx::default();
    group.bench_function(format!("proof creation ({} gates)", num_gates), |b| {
        b.iter(|| ctx.create_proof())
    });
}

pub fn bench_proof_verification(c: &mut Criterion) {
    let mut group = c.benchmark_group("Proof verification");
    group
        .measurement_time(Duration::from_secs(200))
        .sample_size(10);

    let ctx = BenchmarkCtx::default();
    let proof = ctx.create_proof();
    group.bench_function("proof verification", |b| {
        b.iter(|| ctx.batch_verification(vec![proof.clone()]))
    });
}

criterion_group!(benches, bench_proof_creation, bench_proof_verification);
criterion_main!(benches);
