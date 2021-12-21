use criterion::{criterion_group, criterion_main, Criterion};
use kimchi::bench::BenchmarkCtx;
use std::time::Duration;

pub fn bench_proof_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("Proof creation");
    group.measurement_time(Duration::from_secs(100));

    let ctx = BenchmarkCtx::new();
    group.bench_function("single proof", |b| b.iter(|| ctx.create_proof()));
}

criterion_group!(benches, bench_proof_creation);
criterion_main!(benches);
