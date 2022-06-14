use criterion::{black_box, criterion_group, criterion_main, Criterion, SamplingMode};
use kimchi::bench::BenchmarkCtx;

pub fn bench_proof_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("Proof creation");
    group.sample_size(10).sampling_mode(SamplingMode::Flat); // for slow benchmarks

    let ctx = BenchmarkCtx::new(1 << 14, 0);
    let srs_len = ctx.index.srs.g.len();
    group.bench_function(format!("proof creation for SRS {srs_len}"), |b| {
        b.iter(|| black_box(ctx.create_proof()))
    });
}

pub fn bench_proof_verification(c: &mut Criterion) {
    let mut group = c.benchmark_group("Proof verification");
    group.sample_size(10).sampling_mode(SamplingMode::Flat); // for slow benchmarks

    let ctx = BenchmarkCtx::new(1 << 14, 0);
    let srs_len = ctx.index.srs.g.len();
    let proof = ctx.create_proof();
    group.bench_function(format!("proof verification for SRS {srs_len}"), |b| {
        b.iter(|| ctx.batch_verification(black_box(vec![proof.clone()])))
    });
}
criterion_group!(benches, bench_proof_creation, bench_proof_verification);
criterion_main!(benches);
