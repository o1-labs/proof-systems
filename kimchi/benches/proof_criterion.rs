#![allow(clippy::unit_arg)]
use criterion::{black_box, criterion_group, criterion_main, Criterion, SamplingMode};
use kimchi::bench::BenchmarkCtx;

pub fn bench_proof_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("Proof creation");
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
}

pub fn bench_proof_creation_mina(c: &mut Criterion) {
    use groupmap::GroupMap;
    use kimchi::{
        bench::{
            bench_arguments_from_file, BaseSpongePallas, BaseSpongeVesta, ScalarSpongePallas,
            ScalarSpongeVesta,
        },
        proof::ProverProof,
    };
    use mina_curves::pasta::{Pallas, Vesta};

    let mut group = c.benchmark_group("Proof creation (mina circuit)");

    // we don't have to be precise with these benches
    group.sampling_mode(SamplingMode::Flat); // for slow benchmarks
    group.sample_size(10); // Limits the number of samples

    // Vesta
    {
        let seeds_vesta: Vec<u64> = vec![
            10596861074504661741,
            11905291666876899086,
            11944131969684269701,
            11989028466209190542,
            12479452507099265722,
            14327630479687750080,
            15291293990426965937,
            15792116159270623099,
            16106463403161176923,
            17016866561918195054,
            1702566697096426944,
        ];

        let srs = kimchi::precomputed_srs::get_srs_test();

        for seed in seeds_vesta {
            let (index, witness, runtime_tables, prev) =
                bench_arguments_from_file::<Vesta, BaseSpongeVesta>(srs.clone(), seed.to_string());

            let group_map = GroupMap::<_>::setup();
            group.bench_function(
                format!("proof creation (mina, vesta, circuit seed {})", seed),
                |b| {
                    b.iter(|| {
                        black_box(ProverProof::create_recursive::<
                            BaseSpongeVesta,
                            ScalarSpongeVesta,
                            _,
                        >(
                            &group_map,
                            witness.clone(),
                            &runtime_tables,
                            &index,
                            prev.clone(),
                            None,
                            &mut rand::rngs::OsRng,
                        ))
                    })
                },
            );
        }
    }

    // Palas
    {
        let seeds_pallas: Vec<u64> = vec![
            1046902090469669730,
            10666926878093284941,
            11077595827393350400,
            11931396553360658508,
            12076254163870571246,
            12283305969043888103,
            14036036535646723534,
            14723393858825727067,
            1492142480766064234,
            1540046002904207613,
            15891712075838566059,
        ];

        let srs = kimchi::precomputed_srs::get_srs_test();

        for seed in seeds_pallas {
            let (index, witness, runtime_tables, prev) =
                bench_arguments_from_file::<Pallas, BaseSpongePallas>(
                    srs.clone(),
                    seed.to_string(),
                );

            let group_map = GroupMap::<_>::setup();
            group.bench_function(
                format!("proof creation (mina, pallas, circuit seed {})", seed),
                |b| {
                    b.iter(|| {
                        black_box(ProverProof::create_recursive::<
                            BaseSpongePallas,
                            ScalarSpongePallas,
                            _,
                        >(
                            &group_map,
                            witness.clone(),
                            &runtime_tables,
                            &index,
                            prev.clone(),
                            None,
                            &mut rand::rngs::OsRng,
                        ))
                    })
                },
            );
        }
    }
}

pub fn bench_proof_verification(c: &mut Criterion) {
    let mut group = c.benchmark_group("Proof verification");

    // Unfortunately, we have to use relatively big sample sizes. With this
    // the noise should be <0.5%
    group.sampling_mode(SamplingMode::Linear);
    group.measurement_time(std::time::Duration::from_secs(300));

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
}

criterion_group!(
    benches,
    bench_proof_creation_mina,
    //bench_proof_creation,
    //bench_proof_verification
);
criterion_main!(benches);
