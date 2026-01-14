//! Benchmarks for gadget output computation.
//!
//! These benchmarks measure the native execution time of each gadget's `output()`
//! method. This represents the non-ZK computation time.

use arrabbiata::circuits::{
    CubicGadget, FibonacciGadget, MinRootGadget, Pair, Scalar, SquaringGadget, TrivialGadget,
    TypedGadget,
};
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use mina_curves::pasta::Fp;

/// Benchmark the trivial gadget (pass-through)
fn bench_trivial_output(c: &mut Criterion) {
    let gadget = TrivialGadget::new();
    let z = Scalar(Fp::from(42u64));

    c.bench_function("trivial_output", |b| {
        b.iter(|| TypedGadget::<Fp>::output(&gadget, black_box(&z)))
    });
}

/// Benchmark the squaring gadget
fn bench_squaring_output(c: &mut Criterion) {
    let gadget = SquaringGadget::new();
    let z = Scalar(Fp::from(2u64));

    c.bench_function("squaring_output", |b| {
        b.iter(|| TypedGadget::<Fp>::output(&gadget, black_box(&z)))
    });
}

/// Benchmark multiple squarings (simulating Repeat)
fn bench_squaring_iterations(c: &mut Criterion) {
    let mut group = c.benchmark_group("squaring_iterations");
    let gadget = SquaringGadget::new();

    for num_iters in [1, 5, 10, 20, 50].iter() {
        group.bench_function(format!("{}_squarings", num_iters), |b| {
            b.iter(|| {
                let mut z = Scalar(Fp::from(2u64));
                for _ in 0..*num_iters {
                    z = TypedGadget::<Fp>::output(&gadget, &z);
                }
                black_box(z)
            })
        });
    }

    group.finish();
}

/// Benchmark the Fibonacci gadget
fn bench_fibonacci_output(c: &mut Criterion) {
    let gadget = FibonacciGadget::new();
    let z = Pair::new(Fp::from(0u64), Fp::from(1u64));

    c.bench_function("fibonacci_output", |b| {
        b.iter(|| TypedGadget::<Fp>::output(&gadget, black_box(&z)))
    });
}

/// Benchmark multiple Fibonacci iterations
fn bench_fibonacci_iterations(c: &mut Criterion) {
    let mut group = c.benchmark_group("fibonacci_iterations");
    let gadget = FibonacciGadget::new();

    for num_iters in [10, 100, 1000].iter() {
        group.bench_function(format!("{}_iterations", num_iters), |b| {
            b.iter(|| {
                let mut z = Pair::new(Fp::from(0u64), Fp::from(1u64));
                for _ in 0..*num_iters {
                    z = TypedGadget::<Fp>::output(&gadget, &z);
                }
                black_box(z)
            })
        });
    }

    group.finish();
}

/// Benchmark the cubic gadget
fn bench_cubic_output(c: &mut Criterion) {
    let gadget = CubicGadget::new();
    let z = Scalar(Fp::from(5u64));

    c.bench_function("cubic_output", |b| {
        b.iter(|| TypedGadget::<Fp>::output(&gadget, black_box(&z)))
    });
}

/// Benchmark MinRoot gadget (VDF) - this is computationally expensive
fn bench_minroot_output(c: &mut Criterion) {
    let mut group = c.benchmark_group("minroot_output");
    group.sample_size(10); // Reduce sample size for expensive benchmark

    let x = Fp::from(3u64);
    let y = Fp::from(5u64);
    let gadget = MinRootGadget::from_input(x, y);
    let z = Pair::new(x, y);

    group.bench_function("1_iteration", |b| {
        b.iter(|| TypedGadget::<Fp>::output(&gadget, black_box(&z)))
    });

    group.finish();
}

/// Benchmark MinRoot iterations
fn bench_minroot_iterations(c: &mut Criterion) {
    let mut group = c.benchmark_group("minroot_iterations");
    group.sample_size(10);

    for num_iters in [1, 5, 10].iter() {
        group.bench_function(format!("{}_iterations", num_iters), |b| {
            b.iter(|| {
                let mut x = Fp::from(3u64);
                let mut y = Fp::from(5u64);
                for _ in 0..*num_iters {
                    let gadget = MinRootGadget::from_input(x, y);
                    let output = TypedGadget::<Fp>::output(&gadget, &Pair::new(x, y));
                    x = output.first;
                    y = output.second;
                }
                black_box(Pair::new(x, y))
            })
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_trivial_output,
    bench_squaring_output,
    bench_squaring_iterations,
    bench_fibonacci_output,
    bench_fibonacci_iterations,
    bench_cubic_output,
    bench_minroot_output,
    bench_minroot_iterations,
);

criterion_main!(benches);
