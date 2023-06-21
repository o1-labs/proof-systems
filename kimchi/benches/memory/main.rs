use benchmarking::{
    runner::{new_benchmark, BenchmarkRunner, CriterionBlackBox},
    Benchmark,
};
use criterion::{
    criterion_group, criterion_main, measurement::Measurement, BenchmarkGroup, BenchmarkId,
    Criterion,
};
use measurement::MaxMemoryUse;
use std::time::Duration;

mod measurement;

///an instrumented allocator that allows to collect stats about heap memory, slow
#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

struct MemoryRunner;
impl BenchmarkRunner for MemoryRunner {
    type Measurement = MaxMemoryUse;

    const NAME: &'static str = "memory";

    fn bench<H: Benchmark>(
        group: &mut BenchmarkGroup<'_, Self::Measurement>,
        p: usize,
        data: H::RefinedData,
    ) {
        let mut m = None;
        group.bench_with_input(BenchmarkId::from_parameter(format!("{p}")), &(), |b, _| {
            let m = m.get_or_insert_with(|| {
                MaxMemoryUse::measure_function(|| {
                    H::function::<CriterionBlackBox>(p, &data);
                })
            });
            b.iter_custom(|iters| {
                let measurement = m.start();
                let measurement = m.end(measurement);
                // without this criterion will see a very a very fast function and request
                // a lot of iterations, resulting in overflow bellow
                std::thread::sleep(Duration::from_millis(200));
                measurement * iters
            });
        });
    }
}
fn all_benches(c: &mut Criterion<MaxMemoryUse>) {
    use kimchi::benchmarks::*;

    let params = benchmarking::params();
    MemoryRunner::message(&params);

    let benches = new_benchmark::<MemoryRunner, Compiling>();
    let benches = benches.add::<Proving>();
    let benches = benches.add::<Verifying>();
    //add a line here to add your benchmark

    benches.run(c, &params);
}

criterion_group!(name = benches; config = MaxMemoryUse::criterion(); targets = all_benches);
criterion_main!(benches);
