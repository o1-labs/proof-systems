use ark_ff::UniformRand;
use criterion::{black_box, criterion_group, criterion_main, Bencher, Criterion};
use mina_curves::pasta::Fp;
use mvpoly::{prime::Dense, MVPoly};

// Using 10 variables, with max degree 3
// Should roughly cover the cases we care about
fn bench_dense_add(c: &mut Criterion) {
    let mut rng = o1_utils::tests::make_test_rng(None);
    let p1: Dense<Fp, 10, 3> = unsafe { Dense::random(&mut rng, None) };
    let p2: Dense<Fp, 10, 3> = unsafe { Dense::random(&mut rng, None) };
    c.bench_function("dense_add", |b: &mut Bencher| {
        b.iter(|| {
            let _ = black_box(&p1) + black_box(&p2);
        })
    });
}

fn bench_dense_mul(c: &mut Criterion) {
    let mut rng = o1_utils::tests::make_test_rng(None);
    c.bench_function("dense_mul", |b: &mut Bencher| {
        b.iter(|| {
            // IMPROVEME: implement mul on references and define the random
            // values before the benchmark
            let p1: Dense<Fp, 10, 3> = unsafe { Dense::random(&mut rng, None) };
            let p2: Dense<Fp, 10, 3> = unsafe { Dense::random(&mut rng, None) };
            let _ = black_box(p1) * black_box(p2);
        })
    });
}

fn bench_dense_neg(c: &mut Criterion) {
    let mut rng = o1_utils::tests::make_test_rng(None);
    let p1: Dense<Fp, 10, 3> = unsafe { Dense::random(&mut rng, None) };
    c.bench_function("dense_neg", |b: &mut Bencher| {
        b.iter(|| {
            let _ = -black_box(&p1);
        })
    });
}

fn bench_dense_sub(c: &mut Criterion) {
    let mut rng = o1_utils::tests::make_test_rng(None);
    let p1: Dense<Fp, 10, 3> = unsafe { Dense::random(&mut rng, None) };
    let p2: Dense<Fp, 10, 3> = unsafe { Dense::random(&mut rng, None) };
    c.bench_function("dense_sub", |b: &mut Bencher| {
        b.iter(|| {
            let _ = black_box(&p1) - black_box(&p2);
        })
    });
}

fn bench_dense_eval(c: &mut Criterion) {
    let mut rng = o1_utils::tests::make_test_rng(None);
    let p1: Dense<Fp, 10, 3> = unsafe { Dense::random(&mut rng, None) };
    let x: [Fp; 10] = std::array::from_fn(|_| Fp::rand(&mut rng));
    c.bench_function("dense_eval", |b: &mut Bencher| {
        b.iter(|| {
            let _ = black_box(&p1).eval(black_box(&x));
        })
    });
}

criterion_group!(
    benches,
    bench_dense_add,
    bench_dense_mul,
    bench_dense_neg,
    bench_dense_sub,
    bench_dense_eval
);
criterion_main!(benches);
