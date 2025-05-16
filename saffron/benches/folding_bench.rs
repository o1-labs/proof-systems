//! Run this bench using `cargo criterion -p saffron --bench folding_bench` or
//! `cargo bench --bench folding_bench`

use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion, SamplingMode};
use kimchi::{circuits::domains::EvaluationDomains, groupmap::GroupMap};
use mina_curves::pasta::Vesta;
use poly_commitment::{commitment::CommitmentCurve, SRS as _};

use saffron::{
    folding::{
        folding_prover, folding_verifier, prove_relaxed, testing::generate_random_inst_wit,
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

    let (core_instance_1, core_witness_1) = generate_random_inst_wit(&srs, domain, &mut rng);
    let (core_instance_2, core_witness_2) = generate_random_inst_wit(&srs, domain, &mut rng);
    let relaxed_instance_2 = core_instance_2.relax();
    let relaxed_witness_2 = core_witness_2.relax(domain.d1);

    assert!(relaxed_instance_2.check_in_language(&srs, domain.d1, &relaxed_witness_2));

    let (relaxed_instance_3, relaxed_witness_3, error_term_1) = folding_prover(
        &srs,
        domain.d1,
        &core_instance_1,
        &core_witness_1,
        &relaxed_instance_2,
        &relaxed_witness_2,
    );

    assert!(relaxed_instance_3.check_in_language(&srs, domain.d1, &relaxed_witness_3));

    assert!(
        folding_verifier(&core_instance_1, &relaxed_instance_2, error_term_1) == relaxed_instance_3
    );

    group.bench_function("folding_prover", |b| {
        b.iter_batched(
            || generate_random_inst_wit(&srs, domain, &mut rng),
            |(core_instance_4, core_witness_4)| {
                black_box(folding_prover(
                    &srs,
                    domain.d1,
                    &core_instance_4,
                    &core_witness_4,
                    &relaxed_instance_3,
                    &relaxed_witness_3,
                ))
            },
            BatchSize::LargeInput,
        )
    });

    group.bench_function("folding_verifier", |b| {
        b.iter_batched(
            || {
                let (core_instance_4, core_witness_4) =
                    generate_random_inst_wit(&srs, domain, &mut rng);
                let (_, _, error_term_2) = folding_prover(
                    &srs,
                    domain.d1,
                    &core_instance_4,
                    &core_witness_4,
                    &relaxed_instance_3,
                    &relaxed_witness_3,
                );
                (core_instance_4, error_term_2)
            },
            |(core_instance_4, error_term_2)| {
                black_box(folding_verifier(
                    &core_instance_4,
                    &relaxed_instance_3,
                    error_term_2,
                ))
            },
            BatchSize::LargeInput,
        )
    });

    let (core_instance_4, core_witness_4) = generate_random_inst_wit(&srs, domain, &mut rng);
    let (relaxed_instance_5, relaxed_witness_5, _error_term_2) = folding_prover(
        &srs,
        domain.d1,
        &core_instance_4,
        &core_witness_4,
        &relaxed_instance_3,
        &relaxed_witness_3,
    );

    group.bench_function("prover_relaxed", |b| {
        b.iter(|| {
            black_box(prove_relaxed(
                &srs,
                domain,
                &group_map,
                &mut rng,
                &relaxed_instance_5,
                &relaxed_witness_5,
            ))
        })
    });

    let proof = prove_relaxed(
        &srs,
        domain,
        &group_map,
        &mut rng,
        &relaxed_instance_5,
        &relaxed_witness_5,
    );

    group.bench_function("verifier_relaxed", |b| {
        b.iter(|| {
            black_box(verify_relaxed(
                &srs,
                domain,
                &group_map,
                &mut rng,
                &relaxed_instance_5,
                &proof,
            ))
        })
    });
}

criterion_group!(benches, bench_folding);
criterion_main!(benches);
