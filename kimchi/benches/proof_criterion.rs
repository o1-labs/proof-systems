#![allow(clippy::unit_arg)]
use criterion::{black_box, criterion_group, criterion_main, Criterion, SamplingMode};
use kimchi::bench::BenchmarkCtx;

pub fn bench_proof_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("proof_creation");
    group.sampling_mode(SamplingMode::Flat); // for slow benchmarks
    group.measurement_time(std::time::Duration::from_secs(90));

    for size in [10, 15, 16] {
        let ctx = BenchmarkCtx::new(size);

        group.bench_function(
            format!(
                "proof creation (SRS size 2^{{{}}}, {} gates)",
                ctx.srs_size(),
                ctx.num_gates
            ),
            |b| b.iter(|| black_box(ctx.create_proof())),
        );
    }

    group.finish()
}

pub fn bench_proof_verification(c: &mut Criterion) {
    let mut group = c.benchmark_group("proof_verification");

    // Unfortunately, we have to use relatively big sample sizes. With this
    // the noise should be <0.5%
    group.sampling_mode(SamplingMode::Linear);
    group.measurement_time(core::time::Duration::from_secs(300));

    for n_gates_log in [10, 15, 16] {
        // averaging over several proofs and contexts, since using
        // just one seems to introduce extra variance.
        let inputs: Vec<_> = (0..20)
            .map(|_| {
                let ctx = BenchmarkCtx::new(n_gates_log);
                let proof = ctx.create_proof();
                (ctx, proof)
            })
            .collect();

        group.bench_function(
            format!(
                "proof verification (SRS size 2^{{{}}}, {} gates)",
                inputs[0].0.srs_size(),
                1 << n_gates_log
            ),
            |b| {
                b.iter_batched(
                    || &inputs[rand::random::<usize>() % inputs.len()],
                    |(ctx, proof)| black_box(ctx.batch_verification(std::slice::from_ref(proof))),
                    criterion::BatchSize::LargeInput,
                )
            },
        );
    }

    group.finish()
}

criterion_group!(benches, bench_proof_creation, bench_proof_verification);
criterion_main!(benches);
