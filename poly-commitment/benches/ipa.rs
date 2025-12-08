//! Run this bench using `cargo criterion -p poly-commitment --bench ipa`

use ark_ff::{UniformRand, Zero};
use ark_poly::{
    univariate::DensePolynomial, DenseUVPolynomial, EvaluationDomain, Evaluations,
    Radix2EvaluationDomain,
};
use criterion::{black_box, criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};
use groupmap::GroupMap;
use mina_curves::pasta::{Fp, Vesta, VestaParameters};
use mina_poseidon::{constants::PlonkSpongeConstantsKimchi, sponge::DefaultFqSponge, FqSponge};
use num_bigint::BigUint;
use o1_utils::{BigUintFieldHelpers, FieldHelpers};
use poly_commitment::{
    commitment::CommitmentCurve, ipa::SRS, utils::DensePolynomialOrEvaluations, PolyComm, SRS as _,
};
use rand::Rng;

fn benchmark_ipa_commit_vesta(c: &mut Criterion) {
    let mut group = c.benchmark_group("IPA Commit");
    let mut rng = o1_utils::tests::make_test_rng(None);

    for srs_size_log in [12, 15, 16].into_iter() {
        let n = 1 << srs_size_log;
        let srs = SRS::<Vesta>::create(n);
        srs.get_lagrange_basis_from_domain_size(n);

        for chunks_n in [1usize, 2, 4, 8].into_iter() {
            group.bench_function(
                format!(
                    "commitment (SRS size 2^{{{}}}, {} chunks)",
                    srs_size_log, chunks_n
                ),
                |b| {
                    b.iter_batched(
                        || {
                            let poly_coefficients: Vec<Fp> =
                                (0..chunks_n * n).map(|_| Fp::rand(&mut rng)).collect();
                            DensePolynomial::<Fp>::from_coefficients_vec(poly_coefficients)
                        },
                        |poly| black_box(srs.commit_non_hiding(&poly, chunks_n)),
                        BatchSize::LargeInput,
                    )
                },
            );
        }
    }
}

// This benchmark demonstrates that
// `commit_evaluations_non_hiding` is generally faster than
// `commit_non_hiding` when committing evaluations; and especially so
// when the evaluations vector is sparse or contains small elements.
fn benchmark_ipa_commit_evals_vesta(c: &mut Criterion) {
    let mut group = c.benchmark_group("IPA Commit Evaluations");
    let mut rng = o1_utils::tests::make_test_rng(None);

    group.measurement_time(core::time::Duration::from_secs(10));

    let srs_size_log = 15;

    let n = 1 << srs_size_log;
    let srs = SRS::<Vesta>::create(n);
    let domain = Radix2EvaluationDomain::new(n).unwrap();
    srs.get_lagrange_basis_from_domain_size(n);

    for sparsity in [0.05, 0.2, 0.5, 0.99].into_iter() {
        for bitlen in [16, 32, 64, 128, 256].into_iter() {
            // When bitlen > |Fp|, Fp::rand() % bitlenmod will return
            // just field value without performing modulo reduction.
            let bitlenmod: BigUint = Fp::from(1).to_biguint() << bitlen;
            group.bench_function(
                format!(
                    "com w/o Lagrange (|SRS| 2^{{{}}}, sparsity {}%, bitlen {})",
                    srs_size_log,
                    (sparsity * 100.0) as usize,
                    bitlen
                ),
                |b| {
                    b.iter_batched(
                        || {
                            let evaluations: Vec<Fp> = (0..n)
                                .map(|_| {
                                    if rng.gen::<f64>() < sparsity {
                                        (Fp::rand(&mut rng).to_biguint() % bitlenmod.clone())
                                            .to_field()
                                            .unwrap()
                                    } else {
                                        Fp::zero()
                                    }
                                })
                                .collect();
                            Evaluations::from_vec_and_domain(evaluations, domain)
                        },
                        |evals| black_box(srs.commit_non_hiding(&evals.interpolate(), 1)),
                        BatchSize::LargeInput,
                    )
                },
            );

            group.bench_function(
                format!(
                    "com Lagrange (|SRS| 2^{{{}}}, sparsity {}%, bitlen {})",
                    srs_size_log,
                    (sparsity * 100.0) as usize,
                    bitlen
                ),
                |b| {
                    b.iter_batched(
                        || {
                            let evaluations: Vec<Fp> = (0..n)
                                .map(|_| {
                                    if rng.gen::<f64>() < sparsity {
                                        (Fp::rand(&mut rng).to_biguint() % bitlenmod.clone())
                                            .to_field()
                                            .unwrap()
                                    } else {
                                        Fp::zero()
                                    }
                                })
                                .collect();
                            Evaluations::from_vec_and_domain(evaluations, domain)
                        },
                        |evals| black_box(srs.commit_evaluations_non_hiding(domain, &evals)),
                        BatchSize::LargeInput,
                    )
                },
            );
        }
    }
}

fn benchmark_ipa_open_vesta(c: &mut Criterion) {
    let mut group = c.benchmark_group("IPA");
    let group_map = <Vesta as CommitmentCurve>::Map::setup();
    let mut rng = o1_utils::tests::make_test_rng(None);

    let elm = vec![Fp::rand(&mut rng), Fp::rand(&mut rng)];
    let polyscale = Fp::rand(&mut rng);
    let evalscale = Fp::rand(&mut rng);
    for log_n in [5, 10].into_iter() {
        let n = 1 << log_n;
        let srs = SRS::<Vesta>::create(n);
        let sponge = DefaultFqSponge::<VestaParameters, PlonkSpongeConstantsKimchi, 55>::new(
            mina_poseidon::pasta::fq_kimchi::static_params(),
        );
        let poly_coefficients: Vec<Fp> = (0..n).map(|_| Fp::rand(&mut rng)).collect();
        let poly = DensePolynomial::<Fp>::from_coefficients_vec(poly_coefficients);
        let poly_commit = srs.commit(&poly.clone(), 1, &mut rng);
        group.bench_with_input(BenchmarkId::new("IPA Vesta open", n), &n, |b, _| {
            b.iter_batched(
                || (poly.clone(), poly_commit.clone()),
                |(poly, poly_commit)| {
                    let polys: Vec<(
                        DensePolynomialOrEvaluations<_, Radix2EvaluationDomain<_>>,
                        PolyComm<_>,
                    )> = vec![(
                        DensePolynomialOrEvaluations::DensePolynomial(&poly),
                        poly_commit.blinders,
                    )];
                    black_box(srs.open(
                        &group_map,
                        &polys,
                        &elm,
                        polyscale,
                        evalscale,
                        sponge.clone(),
                        &mut rng,
                    ))
                },
                BatchSize::SmallInput,
            );
        });
    }
}

criterion_group!(
    benches,
    benchmark_ipa_commit_vesta,
    benchmark_ipa_commit_evals_vesta,
    benchmark_ipa_open_vesta
);
criterion_main!(benches);
