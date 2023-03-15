use criterion::{
    black_box, criterion_group, criterion_main,
    measurement::{Measurement, ValueFormatter},
    BenchmarkId, Criterion, SamplingMode,
};
use dhat::HeapStats;
use kimchi::bench::BenchmarkCtx;
use rand::Rng;

/// A memory measurement for criterion, could be of interest to extract it into its own module
/// and document it more if we want to use it for other benchmarks
struct MaxMemoryUse;
impl MaxMemoryUse {
    fn criterion() -> Criterion<MaxMemoryUse> {
        Criterion::default().with_measurement(MaxMemoryUse)
    }
}
struct MemoryFormater;

enum Unit {
    B,
    KB,
    MB,
    GB,
}
impl Unit {
    fn factor_and_unit(typical: f64) -> (f64, Self) {
        use Unit::*;
        let (unit, denominator) = match typical as u64 {
            //should decide between powers of ten or two
            // x if x < 1 << 10 => (B, 1),
            // x if x < 1 << 20 => (KB, 1 << 10),
            // x if x < 1 << 30 => (MB, 1 << 20),
            // _ => (GB, 1 << 30),
            x if x < 1 << 10 => (B, 1),
            x if x < 1 << 20 => (KB, 1000),
            x if x < 1 << 30 => (MB, 1000 * 1000),
            _ => (GB, 1000 * 1000 * 1000),
        };
        (1.0 / denominator as f64, unit)
    }
}
impl ValueFormatter for MemoryFormater {
    fn scale_values(&self, typical_value: f64, values: &mut [f64]) -> &'static str {
        let (factor, unit) = Unit::factor_and_unit(typical_value);
        for v in values.iter_mut() {
            *v *= factor;
            assert!(!v.is_nan())
        }
        match unit {
            Unit::B => "B",
            Unit::KB => "KB",
            Unit::MB => "MB",
            Unit::GB => "GB",
        }
    }

    fn scale_throughputs(
        &self,
        typical_value: f64,
        throughput: &criterion::Throughput,
        values: &mut [f64],
    ) -> &'static str {
        let t = match throughput {
            criterion::Throughput::Elements(elems) => (*elems) as f64,
            _ => todo!(),
        };
        let (factor, unit) = Unit::factor_and_unit(typical_value / t);
        for v in values.iter_mut() {
            *v /= t;
            *v *= factor;
            assert_ne!(v, &f64::NAN);
        }

        // "proofs"
        match unit {
            Unit::B => "B/proof",
            Unit::KB => "KB/proof",
            Unit::MB => "MB/proof",
            Unit::GB => "GB/proof",
        }
    }

    fn scale_for_machines(&self, _values: &mut [f64]) -> &'static str {
        "B"
    }
}
struct Bytes(usize);

impl Measurement for MaxMemoryUse {
    type Intermediate = (dhat::HeapStats, dhat::Profiler);

    type Value = Bytes;

    fn start(&self) -> Self::Intermediate {
        let profiler = dhat::Profiler::builder().testing().build();
        (HeapStats::get(), profiler)
    }

    fn end(&self, i: Self::Intermediate) -> Self::Value {
        let now = HeapStats::get();
        assert!(now.max_bytes >= i.0.max_bytes);

        let bytes = now.max_bytes;
        let mut rng = rand::thread_rng();
        assert!(bytes > 200);
        let e = rng.gen_range(0..bytes) / 200;
        let sign: bool = rng.gen();
        let bytes = if sign { bytes + e } else { bytes - e };

        let bytes = std::cmp::max(bytes, 1);

        Bytes(bytes)
    }

    fn add(&self, v1: &Self::Value, v2: &Self::Value) -> Self::Value {
        let (Bytes(a), Bytes(b)) = (v1, v2);
        Bytes(a + b)
    }

    fn zero(&self) -> Self::Value {
        Bytes(0)
    }

    fn to_f64(&self, Bytes(val): &Self::Value) -> f64 {
        let v = *val as f64;
        assert!(!v.is_nan());
        if v.is_sign_negative() {
            panic!("to negative {v}");
        }
        v
    }

    fn formatter(&self) -> &dyn criterion::measurement::ValueFormatter {
        &MemoryFormater
    }
}

const PROOFS: usize = 10;

///an instrumented allocator that allows to collect stats about heap memory, slow
#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

fn amortization(c: &mut Criterion<MaxMemoryUse>) {
    let mut group = c.benchmark_group("amortization-cm");

    let ctx = BenchmarkCtx::new(1 << 16);
    let proof_and_public = ctx.create_proof();
    let proofs: Vec<_> = std::iter::repeat(proof_and_public)
        .take(1 << PROOFS)
        .collect();

    group.sample_size(10);
    group.sampling_mode(SamplingMode::Flat);
    for size in 0..=PROOFS {
        group.throughput(criterion::Throughput::Elements(1 << size));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("2^{size}")),
            &(),
            |b, _| {
                b.iter_custom(|iters| {
                    let m = MaxMemoryUse;
                    let start = m.start();
                    ctx.batch_verification(black_box(&proofs[0..(1 << size)]));
                    let end = m.end(start);
                    let m = end.0 as u64 * iters;
                    Bytes(m as usize)
                });
            },
        );
    }
}
criterion_group! {name = benches;config = MaxMemoryUse::criterion();targets = amortization}
criterion_main!(benches);
