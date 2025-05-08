//! Run this bench using `cargo criterion -p saffron --bench read_proof_bench`

use ark_ff::{One, UniformRand, Zero};
use ark_poly::{univariate::DensePolynomial, Evaluations};
use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
use kimchi::{
    circuits::domains::EvaluationDomains, groupmap::GroupMap, precomputed_srs::get_srs_test,
};
use mina_curves::pasta::{Fp, Vesta};
use once_cell::sync::Lazy;
use poly_commitment::{commitment::CommitmentCurve, SRS as _};
use rand::rngs::OsRng;
use saffron::{
    read_proof::{prove, verify},
    ScalarField, SRS_SIZE,
};

static DOMAIN: Lazy<EvaluationDomains<ScalarField>> =
    Lazy::new(|| EvaluationDomains::<ScalarField>::create(SRS_SIZE).unwrap());

static GROUP_MAP: Lazy<<Vesta as CommitmentCurve>::Map> =
    Lazy::new(<Vesta as CommitmentCurve>::Map::setup);

fn generate_test_data(
    size: usize,
) -> (Vec<ScalarField>, Vec<ScalarField>, Vec<ScalarField>, Vesta) {
    let mut rng = o1_utils::tests::make_test_rng(None);

    // Generate data with specified size
    let data: Vec<ScalarField> = (0..size).map(|_| Fp::rand(&mut rng)).collect();

    let srs = get_srs_test();

    // Create data commitment
    let data_poly: DensePolynomial<ScalarField> =
        Evaluations::from_vec_and_domain(data.clone(), DOMAIN.d1).interpolate();
    let data_comm: Vesta = srs.commit_non_hiding(&data_poly, 1).chunks[0];

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
    let (data, query, answer, data_comm) = generate_test_data(SRS_SIZE);

    let srs = get_srs_test();

    let description = format!("prove size {}", SRS_SIZE);
    c.bench_function(description.as_str(), |b| {
        b.iter_batched(
            || OsRng,
            |mut rng| {
                black_box(prove(
                    *DOMAIN,
                    &srs,
                    &GROUP_MAP,
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
    let (data, query, answer, data_comm) = generate_test_data(SRS_SIZE);

    let srs = get_srs_test();

    // Create proof first
    let mut rng = OsRng;
    let proof = prove(
        *DOMAIN,
        &srs,
        &GROUP_MAP,
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
                    *DOMAIN, &srs, &GROUP_MAP, &mut rng, &data_comm, &proof,
                ))
            },
            BatchSize::SmallInput,
        )
    });
}

criterion_group!(benches, bench_read_proof_prove, bench_read_proof_verify);
criterion_main!(benches);
