//! Run this bench using `cargo criterion -p saffron --bench read_proof_bench`

use ark_ff::UniformRand;
use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
use kimchi::{circuits::domains::EvaluationDomains, groupmap::GroupMap};
use poly_commitment::{commitment::CommitmentCurve, ipa::SRS, SRS as _};
use rand::rngs::OsRng;
use saffron::{
    commitment::{commit_poly, Commitment},
    read_proof::{prove, verify, Query},
    storage::Data,
    Curve, ScalarField, SRS_SIZE,
};

fn generate_test_data(
    srs: &SRS<Curve>,
    domain: EvaluationDomains<ScalarField>,
    size: usize,
) -> (Data<ScalarField>, Query, Commitment<Curve>, Curve) {
    let mut rng = o1_utils::tests::make_test_rng(None);

    // Generate data with specified size
    let data = Data {
        data: (0..size).map(|_| ScalarField::rand(&mut rng)).collect(),
    };

    // Create data commitment
    let data_comm = data.to_commitment(srs);

    // Generate query (about 10% of positions will be queried)
    let query = Query::random(0.1, SRS_SIZE);

    let query_comm = commit_poly(srs, &query.to_polynomial(domain.d1));

    (data, query, data_comm, query_comm)
}

fn bench_read_proof_prove(c: &mut Criterion) {
    let srs = poly_commitment::precomputed_srs::get_srs_test();
    let group_map = <Curve as CommitmentCurve>::Map::setup();
    let domain: EvaluationDomains<ScalarField> = EvaluationDomains::create(srs.size()).unwrap();

    let (data, query, data_comm, query_comm) = generate_test_data(&srs, domain, SRS_SIZE);

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
                    &data,
                    &query,
                    &data_comm,
                    &query_comm,
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

    let (data, query, data_comm, query_comm) = generate_test_data(&srs, domain, SRS_SIZE);

    // Create proof first
    let mut rng = OsRng;
    let proof = prove(
        &srs,
        domain,
        &group_map,
        &mut rng,
        &data,
        &query,
        &data_comm,
        &query_comm,
    );

    let description = format!("verify size {}", SRS_SIZE);
    c.bench_function(description.as_str(), |b| {
        b.iter_batched(
            || OsRng,
            |mut rng| {
                black_box(verify(
                    &srs,
                    domain,
                    &group_map,
                    &mut rng,
                    &data_comm,
                    &query_comm,
                    &proof,
                ))
            },
            BatchSize::SmallInput,
        )
    });
}

criterion_group!(benches, bench_read_proof_prove, bench_read_proof_verify);
criterion_main!(benches);
