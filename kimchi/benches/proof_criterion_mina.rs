#![allow(clippy::unit_arg)]
use criterion::{black_box, criterion_group, criterion_main, Criterion, SamplingMode};
use groupmap::GroupMap;
use kimchi::{
    bench::{
        bench_arguments_from_file, BaseSpongePallas, BaseSpongeVesta, ScalarSpongePallas,
        ScalarSpongeVesta,
    },
    curve::KimchiCurve,
    proof::ProverProof,
};
use mina_curves::pasta::{Pallas, Vesta};

pub fn bench_proof_creation_mina(c: &mut Criterion) {
    let mut group = c.benchmark_group("proof_creation_mina");
    // we don't have to be precise with these benches
    group.sampling_mode(SamplingMode::Flat); // for slow benchmarks

    group.sample_size(10); // Limits the number of samples

    let filename = std::env::var("BENCH_PROOF_CREATION_MINA_INPUTS").unwrap();

    // Parse filename "kimchi_inputs_CURVENAME_SEED.set" into two parameters
    let (curve_name, seed): (&str, &str) = filename
        .split('/')
        .last()
        .unwrap()
        .strip_prefix("kimchi_inputs_")
        .unwrap()
        .strip_suffix(".set")
        .unwrap()
        .split_once('_')
        .unwrap();

    if curve_name == Vesta::NAME {
        // Vesta
        let srs = kimchi::precomputed_srs::get_srs_test();
        let (index, witness, runtime_tables, prev) =
            bench_arguments_from_file::<Vesta, BaseSpongeVesta>(srs.clone(), filename.clone());

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
    } else if curve_name == Pallas::NAME {
        // Pallas
        let srs = kimchi::precomputed_srs::get_srs_test();
        let (index, witness, runtime_tables, prev) =
            bench_arguments_from_file::<Pallas, BaseSpongePallas>(srs.clone(), filename.clone());

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
    } else {
        panic!("Unsupported curve: {}", curve_name);
    }

    group.finish()
}

criterion_group!(benches, bench_proof_creation_mina,);
criterion_main!(benches);
