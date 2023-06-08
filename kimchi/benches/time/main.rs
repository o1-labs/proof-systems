use benchmarking::Benchmark;
use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};
use std::marker::PhantomData;

mod sample_benches;

trait Benchmarks {
    fn run(c: &mut Criterion);
}
impl Benchmarks for () {
    fn run(_c: &mut Criterion) {}
}

struct AddBenchmark<H: Benchmark, T: Benchmarks>(PhantomData<(H, T)>);
impl<H: Benchmark, T: Benchmarks> Benchmarks for AddBenchmark<H, T> {
    fn run(c: &mut Criterion) {
        //run previous
        T::run(c);
        // run self
        let data = H::prepare_data();
        let parameters = H::default_parameters().unwrap_or(vec![8, 9, 10, 12, 14, 16]);
        //bench it
        {
            let mut group = c.benchmark_group(std::any::type_name::<H>());
            group.sample_size(10);
            //H::function(parameter, &data);

            for p in [8, 9, 10] {
                let data = H::refine_data(p, &data);

                group.throughput(criterion::Throughput::Elements(1 << p));
                group.bench_with_input(
                    BenchmarkId::from_parameter(format!("-{p}")),
                    &(),
                    |b, _| {
                        b.iter_batched(
                            || &data,
                            |input| H::function(p, input),
                            BatchSize::SmallInput,
                        );
                    },
                );
            }
        }
    }
}
impl<H: Benchmark, T: Benchmarks> AddBenchmark<H, T> {
    fn add<N: Benchmark>(self) -> AddBenchmark<N, Self> {
        AddBenchmark(PhantomData)
    }
    fn run(&self, c: &mut Criterion) {
        <Self as Benchmarks>::run(c)
    }
}
fn new_benchmark<B: Benchmark>() -> AddBenchmark<B, ()> {
    AddBenchmark(PhantomData)
}
// fn chain<H: Benchmark, T: Benchmarks>(benches: T) -> AddBenchmark<H, T> {
// AddBenchmark(PhantomData)
// }

fn all_benches(c: &mut Criterion) {
    println!("{:?}", std::env::args());
    use sample_benches::*;
    let benches = new_benchmark::<Compiling>();
    let benches = benches.add::<Proving>();
    let benches = benches.add::<Verifying>();
    benches.run(c)
}

criterion_group!(benches, all_benches);
criterion_main!(benches);
