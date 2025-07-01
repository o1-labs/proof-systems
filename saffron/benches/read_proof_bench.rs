//! Run this bench using `cargo criterion -p saffron --bench read_proof_bench`

use ark_ff::{One, UniformRand, Zero};
use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
use kimchi::{circuits::domains::EvaluationDomains, groupmap::GroupMap};
use mina_curves::pasta::Fp;
use poly_commitment::{commitment::CommitmentCurve, ipa::SRS, SRS as _};
use rand::rngs::OsRng;
use saffron::{
    commitment::Commitment,
    read_proof::{prove, verify},
    Curve, ScalarField, SRS_SIZE,
};

fn generate_test_data(
    srs: &SRS<Curve>,
    size: usize,
) -> (
    Vec<ScalarField>,
    Vec<ScalarField>,
    Vec<ScalarField>,
    Commitment<Curve>,
) {
    let mut rng = o1_utils::tests::make_test_rng(None);

    // Generate data with specified size
    let data: Vec<ScalarField> = (0..size).map(|_| Fp::rand(&mut rng)).collect();

    // Create data commitment
    let data_comm = Commitment::from_data(srs, &data);

    // Generate query (about 10% of positions will be queried)
    let query: Vec<ScalarField> = (0..size)
        .map(|_| {
            if rand::random::<f32>() < 0.1 {
                Fp::one()
            } else {
                Fp::zero()
            }
        })
        .collect();

    // Compute answer as data * query
    let answer: Vec<ScalarField> = data.iter().zip(query.iter()).map(|(d, q)| *d * q).collect();

    (data, query, answer, data_comm)
}

fn bench_read_proof_prove(c: &mut Criterion) {
    let srs = poly_commitment::precomputed_srs::get_srs_test();
    let group_map = <Curve as CommitmentCurve>::Map::setup();
    let domain: EvaluationDomains<ScalarField> = EvaluationDomains::create(srs.size()).unwrap();

    let (data, query, answer, data_comm) = generate_test_data(&srs, SRS_SIZE);

    let description = format!("prove size {}", SRS_SIZE);
    c.bench_function(description.as_str(), |b| {
        b.iter_batched(
            || OsRng,
            |mut rng| {
                black_box(prove(
                    &srs,
                    domain,
                    &group_map,
                    &mut rng,
                    data.as_slice(),
                    query.as_slice(),
                    answer.as_slice(),
                    &data_comm,
                ))
            },
            BatchSize::NumIterations(10),
        )
    });
}

fn bench_read_proof_verify(c: &mut Criterion) {
    let srs = poly_commitment::precomputed_srs::get_srs_test();
    let group_map = <Curve as CommitmentCurve>::Map::setup();
    let domain: EvaluationDomains<ScalarField> = EvaluationDomains::create(srs.size()).unwrap();

    let (data, query, answer, data_comm) = generate_test_data(&srs, SRS_SIZE);

    // Create proof first
    let mut rng = OsRng;
    let proof = prove(
        &srs,
        domain,
        &group_map,
        &mut rng,
        data.as_slice(),
        query.as_slice(),
        answer.as_slice(),
        &data_comm,
    );

    let description = format!("verify size {}", SRS_SIZE);
    c.bench_function(description.as_str(), |b| {
        b.iter_batched(
            || OsRng,
            |mut rng| {
                black_box(verify(
                    &srs, domain, &group_map, &mut rng, &data_comm, &proof,
                ))
            },
            BatchSize::SmallInput,
        )
    });
}

criterion_group!(benches, bench_read_proof_prove, bench_read_proof_verify);
criterion_main!(benches);
