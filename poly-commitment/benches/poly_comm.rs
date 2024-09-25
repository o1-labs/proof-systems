use ark_ec::{short_weierstrass_jacobian::GroupAffine, SWModelParameters};
use ark_ff::{PrimeField, UniformRand};
use criterion::{black_box, criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};
use mina_curves::pasta::{Pallas, Vesta};
use poly_commitment::PolyComm;
use rand_core::{CryptoRng, RngCore};

fn helper_generate_random_elliptic_curve_point<RNG, P: SWModelParameters>(
    rng: &mut RNG,
) -> GroupAffine<P>
where
    P::BaseField: PrimeField,
    RNG: RngCore + CryptoRng,
{
    let p1_x = P::BaseField::rand(rng);
    let mut p1: Option<GroupAffine<P>> = GroupAffine::<P>::get_point_from_x(p1_x, false);
    while p1.is_none() {
        let p1_x = P::BaseField::rand(rng);
        p1 = GroupAffine::<P>::get_point_from_x(p1_x, false);
    }
    let p1: GroupAffine<P> = p1.unwrap().scale_by_cofactor().into();
    p1
}

fn generate_poly_comm_pallas<RNG>(rng: &mut RNG, n: usize) -> PolyComm<Pallas>
where
    RNG: RngCore + CryptoRng,
{
    let elems: Vec<Pallas> = (0..n)
        .map(|_| helper_generate_random_elliptic_curve_point(rng))
        .collect();
    PolyComm::new(elems)
}

fn generate_poly_comm_vesta<RNG>(rng: &mut RNG, n: usize) -> PolyComm<Vesta>
where
    RNG: RngCore + CryptoRng,
{
    let elems: Vec<Vesta> = (0..n)
        .map(|_| helper_generate_random_elliptic_curve_point(rng))
        .collect();
    PolyComm::new(elems)
}

fn benchmark_polycomm_add(c: &mut Criterion) {
    let mut group = c.benchmark_group("PolyComm Add");
    let mut rng = o1_utils::tests::make_test_rng(None);

    for n in [16, 32, 64, 128, 256, 1 << 10, 1 << 14, 1 << 15].into_iter() {
        let poly1: PolyComm<Pallas> = generate_poly_comm_pallas(&mut rng, n);
        let poly2: PolyComm<Pallas> = generate_poly_comm_pallas(&mut rng, n);
        group.bench_with_input(BenchmarkId::new("PolyComm Add Pallas", n), &n, |b, _| {
            b.iter_batched(
                || (poly1.clone(), poly2.clone()),
                |(poly1, poly2)| {
                    black_box(&poly1 + &poly2);
                },
                BatchSize::SmallInput,
            )
        });

        let poly1: PolyComm<Vesta> = generate_poly_comm_vesta(&mut rng, n);
        let poly2: PolyComm<Vesta> = generate_poly_comm_vesta(&mut rng, n);
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
        let poly1: PolyComm<Pallas> = generate_poly_comm_pallas(&mut rng, n);
        let poly2: PolyComm<Pallas> = generate_poly_comm_pallas(&mut rng, n);
        group.bench_with_input(BenchmarkId::new("PolyComm Sub Pallas", n), &n, |b, _| {
            b.iter_batched(
                || (poly1.clone(), poly2.clone()),
                |(poly1, poly2)| {
                    black_box(&poly1 - &poly2);
                },
                BatchSize::SmallInput,
            )
        });

        let poly1: PolyComm<Vesta> = generate_poly_comm_vesta(&mut rng, n);
        let poly2: PolyComm<Vesta> = generate_poly_comm_vesta(&mut rng, n);
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
