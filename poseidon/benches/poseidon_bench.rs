use ark_ff::Zero;
use criterion::{criterion_group, criterion_main, Criterion};
use mina_curves::pasta::{wasm_friendly::Fp9, Fp};
use mina_poseidon::{
    constants::PlonkSpongeConstantsKimchi,
    pasta::fp_kimchi as SpongeParametersKimchi,
    poseidon::{ArithmeticSponge as Poseidon, ArithmeticSpongeParams, Sponge},
};
use once_cell::sync::Lazy;

pub fn bench_poseidon_kimchi(c: &mut Criterion) {
    let mut group = c.benchmark_group("Poseidon");
    group.sample_size(100);

    // Chain of hashes, starting from a random value
    group.bench_function("poseidon_hash_kimchi", |b| {
        let mut hash: Fp = rand::random();
        let mut poseidon = Poseidon::<Fp, PlonkSpongeConstantsKimchi>::new(
            SpongeParametersKimchi::static_params(),
        );

        // poseidon.absorb(&[Fp::zero()]);
        // println!("{}", poseidon.squeeze());

        b.iter(|| {
            poseidon.absorb(&[hash]);
            hash = poseidon.squeeze();
        })
    });

    // same as above but with Fp9
    group.bench_function("poseidon_hash_kimchi_fp9", |b| {
        let mut hash: Fp9 = Fp9::zero();
        let mut poseidon = Poseidon::<Fp9, PlonkSpongeConstantsKimchi>::new(fp9_static_params());

        // poseidon.absorb(&[Fp9::zero()]);
        // println!("{}", poseidon.squeeze());

        b.iter(|| {
            poseidon.absorb(&[hash]);
            hash = poseidon.squeeze();
        })
    });

    group.finish();
}

criterion_group!(benches, bench_poseidon_kimchi);
criterion_main!(benches);

// sponge params for Fp9

fn fp9_sponge_params() -> ArithmeticSpongeParams<Fp9> {
    let params = SpongeParametersKimchi::params();

    // leverage .into() to convert from Fp to Fp9
    ArithmeticSpongeParams::<Fp9> {
        round_constants: params
            .round_constants
            .into_iter()
            .map(|x| x.into_iter().map(Fp9::from).collect())
            .collect(),
        mds: params
            .mds
            .into_iter()
            .map(|x| x.into_iter().map(Fp9::from).collect())
            .collect(),
    }
}
fn fp9_static_params() -> &'static ArithmeticSpongeParams<Fp9> {
    static PARAMS: Lazy<ArithmeticSpongeParams<Fp9>> = Lazy::new(fp9_sponge_params);
    &PARAMS
}
