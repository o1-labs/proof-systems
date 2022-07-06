use criterion::{criterion_group, criterion_main, Criterion};
use mina_hasher::{create_kimchi, create_legacy, Hashable, ROInput};
use oracle::pasta::{self, fp_kimchi_params, fp_legacy_params};

#[derive(Debug, Clone)]
struct Foo;

impl Hashable for Foo {
    type D = ();

    fn to_roinput(&self) -> ROInput {
        ROInput::new()
    }

    fn domain_string(_: Self::D) -> Option<String> {
        None
    }
}

pub fn bench_hasher_init(c: &mut Criterion) {
    {
        let mut group = c.benchmark_group("legacy");
        group.bench_function("fp_legacy::params()", |b| {
            b.iter(|| pasta::fp_legacy::params())
        });
        group.bench_function("fp_legacy_params()", |b| b.iter(|| fp_legacy_params()));
        group.bench_function("create_legacy()", |b| b.iter(|| create_legacy::<Foo>(())));
    }
    {
        let mut group = c.benchmark_group("kimchi");
        group.bench_function("fp_kimchi::params()", |b| {
            b.iter(|| pasta::fp_kimchi::params())
        });
        group.bench_function("fp_kimchi_params()", |b| b.iter(|| fp_kimchi_params()));
        group.bench_function("create_kimchi()", |b| b.iter(|| create_kimchi::<Foo>(())));
    }
}

criterion_group!(benches, bench_hasher_init);
criterion_main!(benches);
