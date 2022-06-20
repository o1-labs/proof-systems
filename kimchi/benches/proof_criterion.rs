use criterion::{black_box, criterion_group, criterion_main, Criterion, SamplingMode};
use kimchi::bench::BenchmarkCtx;

pub fn bench_proof_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("Proof creation");
    group.sample_size(10).sampling_mode(SamplingMode::Flat); // for slow benchmarks

    let ctx = BenchmarkCtx::new(1 << 10);
    group.bench_function(
        format!("proof creation (SRS size 2^{})", ctx.srs_size()),
        |b| b.iter(|| black_box(ctx.create_proof())),
    );

    let ctx = BenchmarkCtx::new(1 << 14);
    group.bench_function(
        format!("proof creation (SRS size 2^{})", ctx.srs_size()),
        |b| b.iter(|| black_box(ctx.create_proof())),
    );

    let proof = ctx.create_proof();

    group.sample_size(100).sampling_mode(SamplingMode::Auto);
    group.bench_function(
        format!("proof verification (SRS size 2^{})", ctx.srs_size()),
        |b| b.iter(|| ctx.batch_verification(black_box(vec![proof.clone()]))),
    );
}

criterion_group!(benches, bench_proof_creation);
criterion_main!(benches);
