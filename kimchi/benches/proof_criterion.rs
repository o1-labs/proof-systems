use criterion::{black_box, criterion_group, criterion_main, Criterion, SamplingMode};
use kimchi::bench::BenchmarkCtx;

pub fn bench_proof_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("Proof creation");
    group.sample_size(10).sampling_mode(SamplingMode::Flat); // for slow benchmarks

    for size in [10, 14] {
        let ctx = BenchmarkCtx::new(size);

        group.bench_function(
            format!("proof creation (SRS size 2^{{{}}}, {} gates)", ctx.srs_size(), ctx.num_gates),
            |b| b.iter(|| black_box(ctx.create_proof())),
        );
    }
}

pub fn bench_proof_verification(c: &mut Criterion) {
    let mut group = c.benchmark_group("Proof verification");
    group.sample_size(100).sampling_mode(SamplingMode::Auto);

    for size in [10, 14] {
        let ctx = BenchmarkCtx::new(size);
        let proof_and_public = ctx.create_proof();

        group.bench_function(
            format!("proof verification (SRS size 2^{{{}}}, {} gates)", ctx.srs_size(), ctx.num_gates),
            |b| b.iter(|| ctx.batch_verification(black_box(&vec![proof_and_public.clone()]))),
        );
    }
}

criterion_group!(benches, bench_proof_creation, bench_proof_verification);
criterion_main!(benches);
