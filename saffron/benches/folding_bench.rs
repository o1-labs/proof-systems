//! Run this bench using `cargo criterion -p saffron --bench folding_bench` or
//! `cargo bench --bench folding_bench`

use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion, SamplingMode};
use kimchi::{circuits::domains::EvaluationDomains, groupmap::GroupMap};
use mina_curves::pasta::Vesta;
use poly_commitment::{commitment::CommitmentCurve, SRS as _};

use saffron::{
    folding::{
        folding_prover, folding_verifier, prove_relaxed,
        testing::{generate_random_inst_wit_core, generate_random_inst_wit_relaxed},
        verify_relaxed,
    },
    ScalarField,
};

fn bench_folding(c: &mut Criterion) {
    let mut group = c.benchmark_group("folding_ip");
    group.sampling_mode(SamplingMode::Linear);
    group.sample_size(30);

    let mut rng = o1_utils::tests::make_test_rng(None);

    let srs = poly_commitment::precomputed_srs::get_srs_test();
    let group_map = <Vesta as CommitmentCurve>::Map::setup();

    let domain: EvaluationDomains<ScalarField> =
        EvaluationDomains::<ScalarField>::create(srs.size()).unwrap();

    group.bench_function("folding_prover", |b| {
        b.iter_batched(
            || {
                let relaxed = generate_random_inst_wit_relaxed(&srs, domain, &mut rng);
                let core = generate_random_inst_wit_core(&srs, domain, &mut rng);
                (core, relaxed)
            },
            |((core_instance, core_witness), (relaxed_instance, relaxed_witness))| {
                black_box(folding_prover(
                    &srs,
                    domain.d1,
                    &core_instance,
                    &core_witness,
                    &relaxed_instance,
                    &relaxed_witness,
                ))
            },
            BatchSize::LargeInput,
        )
    });

    group.bench_function("folding_verifier", |b| {
        b.iter_batched(
            || {
                let (relaxed_instance, relaxed_witness) =
                    generate_random_inst_wit_relaxed(&srs, domain, &mut rng);
                let (core_instance, core_witness) =
                    generate_random_inst_wit_core(&srs, domain, &mut rng);
                let (_, _, cross_term) = folding_prover(
                    &srs,
                    domain.d1,
                    &core_instance,
                    &core_witness,
                    &relaxed_instance,
                    &relaxed_witness,
                );
                (core_instance, relaxed_instance, cross_term)
            },
            |(core_instance, relaxed_instance, cross_term)| {
                black_box(folding_verifier(
                    &core_instance,
                    &relaxed_instance,
                    cross_term,
                ))
            },
            BatchSize::LargeInput,
        )
    });

    group.bench_function("prover_relaxed", |b| {
        b.iter_batched(
            || generate_random_inst_wit_relaxed(&srs, domain, &mut rng),
            |(relaxed_instance, relaxed_witness)| {
                black_box(prove_relaxed(
                    &srs,
                    domain,
                    &group_map,
                    &mut rand::thread_rng(), // it is not possible to pass &rng to both arguments of iter_batched
                    &relaxed_instance,
                    &relaxed_witness,
                ))
            },
            BatchSize::LargeInput,
        )
    });

    let (relaxed_instance, relaxed_witness) =
        generate_random_inst_wit_relaxed(&srs, domain, &mut rng);
    let proof = prove_relaxed(
        &srs,
        domain,
        &group_map,
        &mut rng,
        &relaxed_instance,
        &relaxed_witness,
    );

    group.bench_function("verifier_relaxed", |b| {
        b.iter(|| {
            black_box(verify_relaxed(
                &srs,
                domain,
                &group_map,
                &mut rng,
                &relaxed_instance,
                &proof,
            ))
        })
    });
}

criterion_group!(benches, bench_folding);
criterion_main!(benches);
