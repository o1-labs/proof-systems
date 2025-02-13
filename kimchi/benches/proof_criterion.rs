#![allow(clippy::unit_arg)]
use criterion::{black_box, criterion_group, criterion_main, Criterion, SamplingMode};
use kimchi::bench::BenchmarkCtx;

pub fn bench_proof_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("Proof creation");
    //group.sample_size(30);
    group.sampling_mode(SamplingMode::Flat); // for slow benchmarks
    group.measurement_time(std::time::Duration::from_secs(90));

    for size in [10, 16] {
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
    use ark_serialize::CanonicalDeserialize;
    use groupmap::GroupMap;
    use kimchi::bench::{BaseSponge, ScalarSponge};
    use kimchi::circuits::lookup::runtime_tables::RuntimeTable;
    use kimchi::circuits::polynomial::COLUMNS;
    use kimchi::proof::{ProverProof, RecursionChallenge};
    use kimchi::prover_index::ProverIndex;
    use mina_curves::pasta::{Fp, Vesta};
    use poly_commitment::commitment::PolyComm;
    use poly_commitment::ipa::OpeningProof;
    use std::{fs::File, io::BufReader};

    let group_map = GroupMap::<_>::setup();

    let mut group = c.benchmark_group("Proof creation (mina circuit)");

    //let seed = "18402993648648599487";
    let seed = "10200493143626649653";

    let bytes1: Vec<u8> = std::fs::read(format!("./test_kimchi_input_{}.ser", seed)).unwrap();
    let (witness, runtime_tables_as_vec, prev_as_pairs): (
        [Vec<_>; COLUMNS],
        Vec<(u32, Vec<Fp>)>,
        Vec<_>,
    ) = CanonicalDeserialize::deserialize_uncompressed(bytes1.as_slice()).unwrap();

    let runtime_tables: Vec<RuntimeTable<_>> = runtime_tables_as_vec
        .into_iter()
        .map(|(id_u32, data)| RuntimeTable {
            id: id_u32 as i32,
            data,
        })
        .collect();

    let prev: Vec<RecursionChallenge<_>> = prev_as_pairs
        .into_iter()
        .map(|(chals, chunks)| RecursionChallenge {
            chals,
            comm: PolyComm { chunks },
        })
        .collect();

    let mut reader2 =
        BufReader::new(File::open(format!("./test_kimchi_index_{}.ser", seed)).unwrap());
    let index_orig: ProverIndex<Vesta, OpeningProof<Vesta>> =
        rmp_serde::from_read(&mut reader2).unwrap();

    let cs = index_orig.cs.clone();
    let endo = cs.endo;
    let srs = kimchi::precomputed_srs::get_srs_test();
    let index: ProverIndex<Vesta, OpeningProof<Vesta>> = ProverIndex::create(cs, endo, srs.into());

    group.bench_function(format!("proof creation (mina)",), |b| {
        b.iter(|| {
            black_box(
                ProverProof::create_recursive::<BaseSponge, ScalarSponge, _>(
                    &group_map,
                    witness.clone(),
                    &runtime_tables,
                    &index,
                    prev.clone(),
                    None,
                    &mut rand::rngs::OsRng,
                ),
            )
        })
    });
}

pub fn bench_proof_verification(c: &mut Criterion) {
    let mut group = c.benchmark_group("Proof verification");

    // Unfortunately, we have to use relatively big sample sizes. With this
    // the noise should be <0.5%
    group.sampling_mode(SamplingMode::Linear);
    group.measurement_time(std::time::Duration::from_secs(300));

    for n_gates_log in [10, 14] {
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
    bench_proof_creation,
    bench_proof_verification
);
criterion_main!(benches);
