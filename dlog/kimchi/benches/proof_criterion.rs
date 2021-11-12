use criterion::{black_box, criterion_group, criterion_main, Criterion};
use kimchi::bench::proof;

pub fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("proof 20", |b| b.iter(|| proof(black_box(20))));
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
