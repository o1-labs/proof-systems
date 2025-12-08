use criterion::{criterion_group, criterion_main, Criterion};
use mina_curves::pasta::Fp;
use mina_poseidon::{
    constants::PlonkSpongeConstantsKimchi,
    pasta::fp_kimchi as SpongeParametersKimchi,
    poseidon::{ArithmeticSponge as Poseidon, Sponge},
};

pub fn bench_poseidon_kimchi(c: &mut Criterion) {
    let mut group = c.benchmark_group("Poseidon");
    group.sample_size(100);

    // Chain of hashes, starting from a random value
    group.bench_function("poseidon_hash_kimchi", |b| {
        let mut hash: Fp = rand::random();
        let mut poseidon = Poseidon::<Fp, PlonkSpongeConstantsKimchi, 55>::new(
            SpongeParametersKimchi::static_params(),
        );

        b.iter(|| {
            poseidon.absorb(&[hash]);
            hash = poseidon.squeeze();
        })
    });

    group.finish();
}

criterion_group!(benches, bench_poseidon_kimchi);
criterion_main!(benches);
