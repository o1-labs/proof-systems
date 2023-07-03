use benchmarking::{
    runner::{BenchmarkRunner, CriterionBlackBox},
    Benchmark,
};
use criterion::{
    criterion_group, criterion_main, BatchSize, BenchmarkGroup, BenchmarkId, Criterion,
    SamplingMode,
};
use criterion_perf_events::Perf;
use perfcnt::linux::{
    CacheId, CacheOpId, CacheOpResultId, HardwareEventType, PerfCounterBuilderLinux,
    SoftwareEventType,
};

struct PerfRunner;
impl BenchmarkRunner for PerfRunner {
    type Measurement = Perf;

    const NAME: &'static str = "perf";

    fn bench<H: Benchmark>(
        group: &mut BenchmarkGroup<'_, Self::Measurement>,
        p: usize,
        data: H::RefinedData,
    ) {
        group.sampling_mode(SamplingMode::Flat);
        group.sample_size(10);
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
#[allow(dead_code)]
enum Event {
    Hardware(HardwareEventType),
    Software(SoftwareEventType),
    Cache {
        cache_id: CacheId,
        cache_op_id: CacheOpId,
        cache_op_result_id: CacheOpResultId,
    },
}
/// this is the event that is being measured
/// note that the report will always say cycles
const EVENT: Event = Event::Hardware(HardwareEventType::CPUCycles);

fn config() -> Criterion<Perf> {
    let perf = match EVENT {
        Event::Hardware(h) => PerfCounterBuilderLinux::from_hardware_event(h),
        Event::Software(s) => PerfCounterBuilderLinux::from_software_event(s),
        Event::Cache {
            cache_id,
            cache_op_id,
            cache_op_result_id,
        } => PerfCounterBuilderLinux::from_cache_event(cache_id, cache_op_id, cache_op_result_id),
    };
    Criterion::default().with_measurement(Perf::new(perf))
}

fn all_benches(c: &mut Criterion<Perf>) {
    use kimchi::benchmarks::*;

    let params = benchmarking::params();
    PerfRunner::message(&params);

    let benches = benchmarking::runner::new_benchmark::<PerfRunner, Compiling>();
    let benches = benches.add::<Proving>();
    let benches = benches.add::<Verifying>();
    //add a line here to add your benchmark

    benches.run(c, &params);
}

criterion_group!(
    name = instructions;
    config = config();
    targets = all_benches
);

criterion_main!(instructions);
