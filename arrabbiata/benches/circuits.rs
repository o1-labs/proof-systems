//! Benchmarks for circuit output computation.
//!
//! These benchmarks measure the native execution time of each circuit's `output()`
//! method. This represents the non-ZK computation time.

use arrabbiata::circuits::{
    CompositeCircuit, CubicCircuit, FibonacciCircuit, MinRootCircuit, SquaringCircuit, StepCircuit,
    TrivialCircuit,
};
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use mina_curves::pasta::Fp;

/// Benchmark the trivial circuit (pass-through)
fn bench_trivial_output(c: &mut Criterion) {
    let circuit = TrivialCircuit::<Fp>::new();
    let z = [Fp::from(42u64)];

    c.bench_function("trivial_output", |b| {
        b.iter(|| circuit.output(black_box(&z)))
    });
}

/// Benchmark the squaring circuit with varying number of squarings
fn bench_squaring_output(c: &mut Criterion) {
    let mut group = c.benchmark_group("squaring_output");

    for num_squarings in [1, 5, 10, 20, 50].iter() {
        let circuit = SquaringCircuit::<Fp>::new(*num_squarings);
        let z = [Fp::from(2u64)];

        group.bench_function(format!("{}_squarings", num_squarings), |b| {
            b.iter(|| circuit.output(black_box(&z)))
        });
    }

    group.finish();
}

/// Benchmark the Fibonacci circuit
fn bench_fibonacci_output(c: &mut Criterion) {
    let circuit = FibonacciCircuit::<Fp>::new();
    let z = [Fp::from(0u64), Fp::from(1u64)];

    c.bench_function("fibonacci_output", |b| {
        b.iter(|| circuit.output(black_box(&z)))
    });
}

/// Benchmark multiple Fibonacci iterations
fn bench_fibonacci_iterations(c: &mut Criterion) {
    let mut group = c.benchmark_group("fibonacci_iterations");
    let circuit = FibonacciCircuit::<Fp>::new();

    for num_iters in [10, 100, 1000].iter() {
        group.bench_function(format!("{}_iterations", num_iters), |b| {
            b.iter(|| {
                let mut z = [Fp::from(0u64), Fp::from(1u64)];
                for _ in 0..*num_iters {
                    z = circuit.output(&z);
                }
                black_box(z)
            })
        });
    }

    group.finish();
}

/// Benchmark the cubic circuit
fn bench_cubic_output(c: &mut Criterion) {
    let circuit = CubicCircuit::<Fp>::new();
    let z = [Fp::from(5u64)];

    c.bench_function("cubic_output", |b| b.iter(|| circuit.output(black_box(&z))));
}

/// Benchmark the composite circuit (demonstrates circuit mixing)
fn bench_composite_output(c: &mut Criterion) {
    let circuit = CompositeCircuit::<Fp>::new();
    let z = [Fp::from(2u64), Fp::from(3u64), Fp::from(1u64)];

    c.bench_function("composite_output", |b| {
        b.iter(|| circuit.output(black_box(&z)))
    });
}

/// Benchmark MinRoot circuit (VDF) - this is computationally expensive
fn bench_minroot_output(c: &mut Criterion) {
    let mut group = c.benchmark_group("minroot_output");
    group.sample_size(10); // Reduce sample size for expensive benchmark

    for num_iters in [1, 5, 10].iter() {
        let (z0, circuit) = MinRootCircuit::<Fp>::new(*num_iters, Fp::from(3u64), Fp::from(5u64));

        group.bench_function(format!("{}_iterations", num_iters), |b| {
            b.iter(|| circuit.output(black_box(&z0)))
        });
    }

    group.finish();
}

/// Benchmark MinRoot circuit creation (including advice computation)
fn bench_minroot_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("minroot_creation");
    group.sample_size(10);

    for num_iters in [1, 5, 10, 20].iter() {
        group.bench_function(format!("{}_iterations", num_iters), |b| {
            b.iter(|| {
                MinRootCircuit::<Fp>::new(
                    *num_iters,
                    black_box(Fp::from(3u64)),
                    black_box(Fp::from(5u64)),
                )
            })
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_trivial_output,
    bench_squaring_output,
    bench_fibonacci_output,
    bench_fibonacci_iterations,
    bench_cubic_output,
    bench_composite_output,
    bench_minroot_output,
    bench_minroot_creation,
);

criterion_main!(benches);
