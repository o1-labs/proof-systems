//! Times `DomainConstantEvaluations::create`. Byte-identical on both sides.
use criterion::{black_box, criterion_group, criterion_main, Criterion, SamplingMode};
use kimchi::circuits::{
    domain_constant_evaluation::DomainConstantEvaluations, domains::EvaluationDomains,
};
use mina_curves::pasta::Fp;

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("dce_create");
    g.sampling_mode(SamplingMode::Flat);
    g.measurement_time(std::time::Duration::from_secs(12));
    g.sample_size(20);
    for log_n in [12u32, 14, 16, 18] {
        let domain = EvaluationDomains::<Fp>::create(1 << log_n).unwrap();
        g.bench_function(format!("create (2^{log_n} rows)"), |b| {
            b.iter(|| {
                black_box(DomainConstantEvaluations::<Fp>::create(
                    black_box(domain),
                    3,
                ))
            })
        });
    }
    g.finish()
}
criterion_group!(benches, bench);
criterion_main!(benches);
