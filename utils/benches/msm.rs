//!
//! You can run this benchmark like so:
//!
//! ```ignore
//! cargo criterion -p o1-utils --bench msm
//! ```
//!
//! It will show you the performance of the arkworks (CPU) and supra (GPU) MSM impls,
//! using different vector lengths.
//!

use ark_ec::{msm::VariableBaseMSM, ProjectiveCurve};
use ark_ff::PrimeField;
use ark_std::{test_rng, UniformRand};
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use mina_curves::pasta::Vesta;
use o1_utils::fast_msm::msm::MultiScalarMultiplication;

fn create_scalars_and_points<G: MultiScalarMultiplication>(
    len: usize,
) -> (Vec<G::ScalarField>, Vec<G>) {
    let mut scalars = Vec::with_capacity(len);
    let mut points = Vec::with_capacity(len);
    for _ in 0..len {
        scalars.push(G::ScalarField::rand(&mut test_rng()));
        points.push(G::Projective::rand(&mut test_rng()).into_affine());
    }
    (scalars, points)
}

pub fn criterion_benchmark(c: &mut Criterion) {
    let (scalars, points) = create_scalars_and_points::<Vesta>(20);
    let scalars_repr: Vec<_> = scalars.iter().map(|x| x.into_repr()).collect();

    c.bench_function("arkworks msm of length 20", |b| {
        b.iter(|| {
            let _ = black_box(VariableBaseMSM::multi_scalar_mul(
                black_box(&points),
                black_box(&scalars_repr),
            ));
        })
    });

    c.bench_function("supra msm of length 20", |b| {
        b.iter(|| {
            let _ = black_box(Vesta::gpu_msm(black_box(&points), black_box(&scalars)));
        })
    });

    let (scalars, points) = create_scalars_and_points::<Vesta>(128);
    let scalars_repr: Vec<_> = scalars.iter().map(|x| x.into_repr()).collect();

    c.bench_function("arkworks msm of length 128", |b| {
        b.iter(|| {
            let _ = black_box(VariableBaseMSM::multi_scalar_mul(
                black_box(&points),
                black_box(&scalars_repr),
            ));
        })
    });

    c.bench_function("supra msm of length 128", |b| {
        b.iter(|| {
            let _ = black_box(Vesta::gpu_msm(black_box(&points), black_box(&scalars)));
        })
    });

    let (scalars, points) = create_scalars_and_points::<Vesta>(200);
    let scalars_repr: Vec<_> = scalars.iter().map(|x| x.into_repr()).collect();

    c.bench_function("arkworks msm of length 200", |b| {
        b.iter(|| {
            let _ = black_box(VariableBaseMSM::multi_scalar_mul(
                black_box(&points),
                black_box(&scalars_repr),
            ));
        })
    });

    c.bench_function("supra msm of length 200", |b| {
        b.iter(|| {
            let _ = black_box(Vesta::gpu_msm(black_box(&points), black_box(&scalars)));
        })
    });

    let (scalars, points) = create_scalars_and_points::<Vesta>(400);
    let scalars_repr: Vec<_> = scalars.iter().map(|x| x.into_repr()).collect();

    c.bench_function("arkworks msm of length 400", |b| {
        b.iter(|| {
            let _ = black_box(VariableBaseMSM::multi_scalar_mul(
                black_box(&points),
                black_box(&scalars_repr),
            ));
        })
    });

    c.bench_function("supra msm of length 400", |b| {
        b.iter(|| {
            let _ = black_box(Vesta::gpu_msm(black_box(&points), black_box(&scalars)));
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
