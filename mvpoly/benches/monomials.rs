use ark_ff::UniformRand;
use criterion::{black_box, criterion_group, criterion_main, Bencher, Criterion};
use mina_curves::pasta::Fp;
use mvpoly::{monomials::Sparse, MVPoly};

// Using 10 variables, with max degree 3
// Should roughly cover the cases we care about
fn bench_sparse_add(c: &mut Criterion) {
    let mut rng = o1_utils::tests::make_test_rng(None);
    let p1: Sparse<Fp, 10, 3> = unsafe { Sparse::random(&mut rng, None) };
    let p2: Sparse<Fp, 10, 3> = unsafe { Sparse::random(&mut rng, None) };
    c.bench_function("sparse_add", |b: &mut Bencher| {
        b.iter(|| {
            let _ = black_box(&p1) + black_box(&p2);
        })
    });
}

fn bench_sparse_mul(c: &mut Criterion) {
    let mut rng = o1_utils::tests::make_test_rng(None);
    c.bench_function("sparse_mul", |b: &mut Bencher| {
        b.iter(|| {
            // IMPROVEME: implement mul on references and define the random
            // values before the benchmark
            let p1: Sparse<Fp, 10, 6> = unsafe { Sparse::random(&mut rng, Some(3)) };
            let p2: Sparse<Fp, 10, 6> = unsafe { Sparse::random(&mut rng, Some(3)) };
            let _ = black_box(p1) * black_box(p2);
        })
    });
}

fn bench_sparse_neg(c: &mut Criterion) {
    let mut rng = o1_utils::tests::make_test_rng(None);
    let p1: Sparse<Fp, 10, 3> = unsafe { Sparse::random(&mut rng, None) };
    c.bench_function("sparse_neg", |b: &mut Bencher| {
        b.iter(|| {
            let _ = -black_box(&p1);
        })
    });
}

fn bench_sparse_sub(c: &mut Criterion) {
    let mut rng = o1_utils::tests::make_test_rng(None);
    let p1: Sparse<Fp, 10, 3> = unsafe { Sparse::random(&mut rng, None) };
    let p2: Sparse<Fp, 10, 3> = unsafe { Sparse::random(&mut rng, None) };
    c.bench_function("sparse_sub", |b: &mut Bencher| {
        b.iter(|| {
            let _ = black_box(&p1) - black_box(&p2);
        })
    });
}

fn bench_sparse_eval(c: &mut Criterion) {
    let mut rng = o1_utils::tests::make_test_rng(None);
    let p1: Sparse<Fp, 10, 3> = unsafe { Sparse::random(&mut rng, None) };
    let x: [Fp; 10] = std::array::from_fn(|_| Fp::rand(&mut rng));
    c.bench_function("sparse_eval", |b: &mut Bencher| {
        b.iter(|| {
            let _ = black_box(&p1).eval(black_box(&x));
        })
    });
}

criterion_group!(
    benches,
    bench_sparse_add,
    bench_sparse_mul,
    bench_sparse_neg,
    bench_sparse_sub,
    bench_sparse_eval
);
criterion_main!(benches);
