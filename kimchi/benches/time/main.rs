use benchmarking::{Benchmark, BlackBox};
use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};
use std::marker::PhantomData;

trait Benchmarks {
    fn run(c: &mut Criterion, params: &Option<Vec<usize>>);
}
impl Benchmarks for () {
    fn run(_c: &mut Criterion, _params: &Option<Vec<usize>>) {}
}

struct CriterionBlackBox;
impl BlackBox for CriterionBlackBox {
    fn black_box<T>(dummy: T) -> T {
        criterion::black_box(dummy)
    }
}

struct AddBenchmark<H: Benchmark, T: Benchmarks>(PhantomData<(H, T)>);
impl<H: Benchmark, T: Benchmarks> Benchmarks for AddBenchmark<H, T> {
    fn run(c: &mut Criterion, params: &Option<Vec<usize>>) {
        //run previous
        T::run(c, params);
        // run self
        let data = H::prepare_data();

        let parameters = H::default_parameters().unwrap_or(vec![8, 9, 10, 12, 14, 16]);
        //override with user provided params
        let parameters = params.as_ref().unwrap_or(&parameters);
        //bench it
        {
            let mut group = c.benchmark_group(std::any::type_name::<H>());
            group.sample_size(10);

            for p in parameters {
                let data = H::refine_data(*p, &data);

                group.throughput(criterion::Throughput::Elements(1 << p));
                group.bench_with_input(BenchmarkId::from_parameter(format!("{p}")), &(), |b, _| {
                    b.iter_batched(
                        || &data,
                        |input| H::function::<CriterionBlackBox>(*p, input),
                        BatchSize::SmallInput,
                    );
                });
            }
        }
    }
}
impl<H: Benchmark, T: Benchmarks> AddBenchmark<H, T> {
    fn add<N: Benchmark>(self) -> AddBenchmark<N, Self> {
        AddBenchmark(PhantomData)
    }
    fn run(&self, c: &mut Criterion, params: &Option<Vec<usize>>) {
        <Self as Benchmarks>::run(c, params)
    }
}
fn new_benchmark<B: Benchmark>() -> AddBenchmark<B, ()> {
    AddBenchmark(PhantomData)
}

fn params() -> Option<Vec<usize>> {
    match std::env::var("PARAMS") {
        Ok(var) => Some(
            (*var)
                .split(',')
                .map(|x| x.trim().parse::<usize>().unwrap())
                .collect(),
        ),
        _ => None,
    }
}

#[cfg(test)]
fn all_benches(c: &mut Criterion) {
    use kimchi::benchmarks::*;

    let params = params();
    println!("\n");
    match params {
        Some(_) => {
            println!("Running time benchmarks with selected parameters");
        }
        None => {
            println!("Running time benchmarks with default parameters");
        }
    }
    println!("You can run specific benchmarks and with custom parameters in the next way:");
    println!("PARAMS=6,8,10 cargo criterion --bench time -- Proving");
    println!("\n");

    let benches = new_benchmark::<Compiling>();
    let benches = benches.add::<Proving>();
    let benches = benches.add::<Verifying>();
    let benches = benches.add::<HashChain>();
    //add a line here to add your benchmark

    benches.run(c, &params);
}

criterion_group!(benches, all_benches);
criterion_main!(benches);
