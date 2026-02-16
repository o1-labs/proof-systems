//! Run this bench using `cargo criterion -p poly-commitment --bench msm`

use ark_ff::UniformRand;
use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
use mina_curves::pasta::{Fp, Vesta};
use poly_commitment::{ipa::SRS, SRS as _};

fn benchmark_msm_vesta(c: &mut Criterion) {
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

/// Experimental results (16 cores desktop, 16 core server) show that
/// splitting the msm function in two leads to fastest performance
/// possible. This effect is most notable for MSM sizes starting from
/// 1024 and more, e.g.:
///
/// MSM/msm vertical (size 2^{10}, threads 1)
///                         time:   [2.0154 ms 2.0276 ms 2.0401 ms]
/// MSM/msm vertical (size 2^{10}, threads 2)
///                         time:   [1.7544 ms 1.7665 ms 1.7815 ms]
/// MSM/msm vertical (size 2^{10}, threads 4)
///                         time:   [1.9586 ms 1.9749 ms 1.9931 ms]
/// MSM/msm vertical (size 2^{10}, threads 8)
///                         time:   [2.2679 ms 2.2902 ms 2.3137 ms]
///
/// For MSM of size 2^8 it's barely noticeable ([787µs, 775µs, 815µs, 954µs]).
///
/// For 2^16 MSM, splitting in 4 chunks is slightly faster than two,
/// but the speedup is not worth the complexity.
///
/// For even bigger MSMs (larger than 2^16), splitting in more chunks
/// (e.g. 4) might be the best solution.
fn benchmark_msm_parallel_vesta(c: &mut Criterion) {
    use ark_ec::{AffineRepr, CurveGroup, PrimeGroup, VariableBaseMSM};
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

criterion_group!(benches, benchmark_msm_parallel_vesta, benchmark_msm_vesta);
criterion_main!(benches);
