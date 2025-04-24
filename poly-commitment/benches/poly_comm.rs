//! Run this bench using `cargo criterion -p poly-commitment --bench poly_comm`

use ark_ec::{
    short_weierstrass::{Affine, SWCurveConfig},
    AffineRepr,
};
use ark_ff::PrimeField;
use criterion::{black_box, criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};
use mina_curves::pasta::{Pallas, Vesta};
use poly_commitment::PolyComm;
use rand_core::{CryptoRng, RngCore};

fn generate_poly_comm<RNG, F: PrimeField, C: SWCurveConfig<ScalarField = F>>(
    rng: &mut RNG,
    n: usize,
) -> PolyComm<Affine<C>>
where
    RNG: RngCore + CryptoRng,
{
    let elems: Vec<Affine<C>> = (0..n)
        .map(|_| {
            let x = F::rand(rng);
            Affine::<C>::generator().mul_bigint(x.into_bigint()).into()
        })
        .collect();
    PolyComm::new(elems)
}

fn benchmark_polycomm_add(c: &mut Criterion) {
    let mut group = c.benchmark_group("PolyComm Add");
    let mut rng = o1_utils::tests::make_test_rng(None);

    for n in [16, 32, 64, 128, 256, 1 << 10, 1 << 14, 1 << 15].into_iter() {
        let poly1: PolyComm<Pallas> = generate_poly_comm(&mut rng, n);
        let poly2: PolyComm<Pallas> = generate_poly_comm(&mut rng, n);
        group.bench_with_input(BenchmarkId::new("PolyComm Add Pallas", n), &n, |b, _| {
            b.iter_batched(
                || (poly1.clone(), poly2.clone()),
                |(poly1, poly2)| {
                    black_box(&poly1 + &poly2);
                },
                BatchSize::SmallInput,
            )
        });

        let poly1: PolyComm<Vesta> = generate_poly_comm(&mut rng, n);
        let poly2: PolyComm<Vesta> = generate_poly_comm(&mut rng, n);
        group.bench_with_input(BenchmarkId::new("PolyComm Add Vesta", n), &n, |b, _| {
            b.iter_batched(
                || (poly1.clone(), poly2.clone()),
                |(poly1, poly2)| {
                    black_box(&poly1 + &poly2);
                },
                BatchSize::SmallInput,
            )
        });
    }
    group.finish();
}

fn benchmark_polycomm_sub(c: &mut Criterion) {
    let mut group = c.benchmark_group("PolyComm Sub");
    let mut rng = o1_utils::tests::make_test_rng(None);

    for n in [16, 32, 64, 128, 256, 1 << 10, 1 << 14, 1 << 15].into_iter() {
        let poly1: PolyComm<Pallas> = generate_poly_comm(&mut rng, n);
        let poly2: PolyComm<Pallas> = generate_poly_comm(&mut rng, n);
        group.bench_with_input(BenchmarkId::new("PolyComm Sub Pallas", n), &n, |b, _| {
            b.iter_batched(
                || (poly1.clone(), poly2.clone()),
                |(poly1, poly2)| {
                    black_box(&poly1 - &poly2);
                },
                BatchSize::SmallInput,
            )
        });

        let poly1: PolyComm<Vesta> = generate_poly_comm(&mut rng, n);
        let poly2: PolyComm<Vesta> = generate_poly_comm(&mut rng, n);
        group.bench_with_input(BenchmarkId::new("PolyComm Sub Vesta", n), &n, |b, _| {
            b.iter_batched(
                || (poly1.clone(), poly2.clone()),
                |(poly1, poly2)| {
                    black_box(&poly1 - &poly2);
                },
                BatchSize::SmallInput,
            )
        });
    }
    group.finish();
}

criterion_group!(benches, benchmark_polycomm_add, benchmark_polycomm_sub);
criterion_main!(benches);
