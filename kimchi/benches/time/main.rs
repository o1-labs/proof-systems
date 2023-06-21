use benchmarking::{
    runner::{BenchmarkRunner, CriterionBlackBox},
    Benchmark,
};
use criterion::{
    criterion_group, criterion_main, measurement::WallTime, BatchSize, BenchmarkGroup, BenchmarkId,
    Criterion,
};

struct TimeRunner;
impl BenchmarkRunner for TimeRunner {
    type Measurement = WallTime;

    const NAME: &'static str = "time";

    fn bench<H: Benchmark>(
        group: &mut BenchmarkGroup<'_, Self::Measurement>,
        p: usize,
        data: H::RefinedData,
    ) {
        group.throughput(criterion::Throughput::Elements(1 << p));
        group.bench_with_input(BenchmarkId::from_parameter(format!("{p}")), &(), |b, _| {
            b.iter_batched(
                || &data,
                |input| H::function::<CriterionBlackBox>(p, input),
                BatchSize::SmallInput,
            );
        });
    }
}

#[cfg(test)]
fn all_benches(c: &mut Criterion) {
    use kimchi::benchmarks::*;

    let params = benchmarking::params();
    TimeRunner::message(&params);

    let benches = benchmarking::runner::new_benchmark::<TimeRunner, Compiling>();
    let benches = benches.add::<Proving>();
    let benches = benches.add::<Verifying>();
    //add a line here to add your benchmark

    benches.run(c, &params);
}

criterion_group!(benches, all_benches);
criterion_main!(benches);
