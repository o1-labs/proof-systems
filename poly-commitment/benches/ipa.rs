use ark_ff::UniformRand;
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, Radix2EvaluationDomain};
use criterion::{black_box, criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};
use groupmap::GroupMap;
use mina_curves::pasta::{Fp, Vesta, VestaParameters};
use mina_poseidon::{constants::PlonkSpongeConstantsKimchi, sponge::DefaultFqSponge, FqSponge};
use poly_commitment::{
    commitment::CommitmentCurve, ipa::SRS, utils::DensePolynomialOrEvaluations, PolyComm, SRS as _,
};

fn benchmark_msm(c: &mut Criterion) {
    use ark_ec::{AffineRepr, VariableBaseMSM};
    use ark_ff::PrimeField;

    let mut group = c.benchmark_group("MSM");
    let mut rng = o1_utils::tests::make_test_rng(None);

    let srs = SRS::<Vesta>::create(1 << 16);
    srs.get_lagrange_basis_from_domain_size(1 << 16);

    for msm_size_log in [8, 10, 12, 14, 16].into_iter() {
        let n = 1 << msm_size_log;
        group.bench_function(format!("msm (size 2^{{{}}})", msm_size_log), |b| {
            b.iter_batched(
                || {
                    let coeffs: Vec<Fp> = (0..n).map(|_| Fp::rand(&mut rng)).collect();
                    coeffs
                },
                |coeffs| black_box(<Vesta as AffineRepr>::Group::msm(&srs.g[0..n], &coeffs)),
                BatchSize::LargeInput,
            )
        });
        group.bench_function(format!("msm bigint (size 2^{{{}}})", msm_size_log), |b| {
            b.iter_batched(
                || {
                    let coeffs: Vec<Fp> = (0..n).map(|_| Fp::rand(&mut rng)).collect();
                    let coeffs_bigint: Vec<_> =
                        coeffs.into_iter().map(|c| c.into_bigint()).collect();
                    coeffs_bigint
                },
                |coeffs_bigint| {
                    black_box(<Vesta as AffineRepr>::Group::msm_bigint(
                        &srs.g,
                        &coeffs_bigint,
                    ))
                },
                BatchSize::LargeInput,
            )
        });
        group.bench_function(
            format!("msm bigint + conversion (size 2^{{{}}})", msm_size_log),
            |b| {
                b.iter_batched(
                    || {
                        let coeffs: Vec<Fp> = (0..n).map(|_| Fp::rand(&mut rng)).collect();
                        coeffs
                    },
                    |coeffs| {
                        black_box(<Vesta as AffineRepr>::Group::msm_bigint(
                            &srs.g,
                            &coeffs
                                .into_iter()
                                .map(|c| c.into_bigint())
                                .collect::<Vec<_>>(),
                        ))
                    },
                    BatchSize::LargeInput,
                )
            },
        );
    }
}

fn benchmark_msm_parallel(c: &mut Criterion) {
    use ark_ec::{AffineRepr, CurveGroup, Group, VariableBaseMSM};
    use rayon::prelude::*;

    let max_threads_global = rayon::max_num_threads();

    let mut group = c.benchmark_group("MSM");
    let mut rng = o1_utils::tests::make_test_rng(None);

    let srs = SRS::<Vesta>::create(1 << 16);
    srs.get_lagrange_basis_from_domain_size(1 << 16);

    for msm_size_log in [8, 10, 12, 14, 16].into_iter() {
        let n = 1 << msm_size_log;
        for thread_num in [1, 2, 4, 8].into_iter() {
            group.bench_function(
                format!(
                    "msm vertical (size 2^{{{}}}, threads {})",
                    msm_size_log, thread_num
                ),
                |b| {
                    b.iter_batched(
                        || {
                            let coeffs: Vec<Fp> = (0..n).map(|_| Fp::rand(&mut rng)).collect();
                            coeffs
                        },
                        |coeffs| {
                            black_box({
                                let sub_g: Vec<_> =
                                    srs.g.chunks(n / thread_num).take(thread_num).collect();
                                coeffs
                                    .into_par_iter()
                                    .chunks(n / thread_num)
                                    .zip(sub_g.into_par_iter())
                                    .map(|(coeffs_chunk, g_chunk)| {
                                        <Vesta as AffineRepr>::Group::msm(g_chunk, &coeffs_chunk)
                                            .unwrap()
                                    })
                                    .reduce(<Vesta as AffineRepr>::Group::generator, |mut l, r| {
                                        l += r;
                                        l
                                    })
                            })
                        },
                        BatchSize::LargeInput,
                    )
                },
            );
        }
    }

    for msm_size_log in [8, 10, 12, 14, 16].into_iter() {
        let n = 1 << msm_size_log;
        for batch_size in [1, 2, 4, 8].into_iter() {
            group.bench_function(
                format!(
                    "msm batched (size 2^{{{}}}, batch size {})",
                    msm_size_log, batch_size
                ),
                |b| {
                    b.iter_batched(
                        || {
                            let coeffs: Vec<Fp> =
                                (0..batch_size * n).map(|_| Fp::rand(&mut rng)).collect();
                            coeffs
                        },
                        |coeffs| {
                            black_box({
                                coeffs
                                    .chunks(n)
                                    .map(|chunk| {
                                        let chunk_res =
                                            <Vesta as AffineRepr>::Group::msm(&srs.g[..n], chunk)
                                                .unwrap();
                                        chunk_res.into_affine()
                                    })
                                    .collect::<Vec<_>>()
                            })
                        },
                        BatchSize::LargeInput,
                    )
                },
            );
            group.bench_function(
                format!(
                    "msm batched *parallel & 2-vertical* (size 2^{{{}}}, batch size {})",
                    msm_size_log, batch_size
                ),
                |b| {
                    let min_len = std::cmp::min(batch_size, max_threads_global / 4);
                    b.iter_batched(
                        || {
                            let coeffs: Vec<Fp> =
                                (0..batch_size * n).map(|_| Fp::rand(&mut rng)).collect();
                            coeffs
                        },
                        |coeffs| {
                            black_box({
                                coeffs
                                    .into_par_iter()
                                    .chunks(n)
                                    .with_min_len(min_len)
                                    .map(|chunk| {
                                        let (r1, r2) = rayon::join(
                                            || {
                                                <Vesta as AffineRepr>::Group::msm(
                                                    &srs.g[..n / 2],
                                                    &chunk[..n / 2],
                                                )
                                                .unwrap()
                                            },
                                            || {
                                                <Vesta as AffineRepr>::Group::msm(
                                                    &srs.g[n / 2..n],
                                                    &chunk[n / 2..n],
                                                )
                                                .unwrap()
                                            },
                                        );

                                        (r1 + r2).into_affine()
                                    })
                                    .collect::<Vec<_>>()
                            })
                        },
                        BatchSize::LargeInput,
                    )
                },
            );
            for max_threads in [2, 4, 8].into_iter().filter(|i| *i <= batch_size) {
                group.bench_function(
                    format!(
                        "msm batched *parallel* (size 2^{{{}}}, batch size {}, max threads {})",
                        msm_size_log, batch_size, max_threads
                    ),
                    |b| {
                        b.iter_batched(
                            || {
                                let coeffs: Vec<Fp> =
                                    (0..batch_size * n).map(|_| Fp::rand(&mut rng)).collect();
                                coeffs
                            },
                            |coeffs| {
                                black_box({
                                    coeffs
                                        .into_par_iter()
                                        .chunks(n)
                                        .with_min_len(batch_size / max_threads)
                                        .map(|chunk| {
                                            let chunk_res = <Vesta as AffineRepr>::Group::msm(
                                                &srs.g[..n],
                                                &chunk,
                                            )
                                            .unwrap();
                                            chunk_res.into_affine()
                                        })
                                        .collect::<Vec<_>>()
                                })
                            },
                            BatchSize::LargeInput,
                        )
                    },
                );
            }
        }
    }
}

fn benchmark_ipa_commit(c: &mut Criterion) {
    let mut group = c.benchmark_group("IPA Commit");
    let mut rng = o1_utils::tests::make_test_rng(None);

    for srs_size_log in [8, 12, 16].into_iter() {
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

fn benchmark_ipa_open(c: &mut Criterion) {
    let mut group = c.benchmark_group("IPA");
    let group_map = <Vesta as CommitmentCurve>::Map::setup();
    let mut rng = o1_utils::tests::make_test_rng(None);

    let elm = vec![Fp::rand(&mut rng), Fp::rand(&mut rng)];
    let polyscale = Fp::rand(&mut rng);
    let evalscale = Fp::rand(&mut rng);
    for log_n in [5, 10].into_iter() {
        let n = 1 << log_n;
        let srs = SRS::<Vesta>::create(n);
        let sponge = DefaultFqSponge::<VestaParameters, PlonkSpongeConstantsKimchi>::new(
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
    benchmark_msm_parallel,
    benchmark_msm,
    benchmark_ipa_commit,
    benchmark_ipa_open
);
criterion_main!(benches);
