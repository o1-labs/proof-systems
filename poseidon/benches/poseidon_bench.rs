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
        let mut hash: Fp9 = Fp9::from(12345u64);
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

pub fn bench_conversions(c: &mut Criterion) {
    let mut group = c.benchmark_group("Conversions");

    group.bench_function("Conversion: fp_to_fp9", |b| {
        b.iter_batched(
            || {
                let x: Fp = rand::random();
                x
            },
            |x| {
                let z: Fp9 = x.into();
                z
            },
            criterion::BatchSize::SmallInput,
        );
    });

    group.bench_function("Conversion: fp_to_fp9, 2^16 elements", |b| {
        b.iter_batched(
            || (0..65536).map(|_| rand::random()).collect(),
            |hashes_fp: Vec<Fp>| {
                let mut hashes_fp9: Vec<Fp9> = Vec::with_capacity(65536);
                for h in hashes_fp.clone().into_iter() {
                    hashes_fp9.push(h.into());
                }
                hashes_fp9
            },
            criterion::BatchSize::SmallInput,
        );
    });
}

pub fn bench_basic_ops(c: &mut Criterion) {
    let mut group = c.benchmark_group("Basic ops");

    group.bench_function("Native multiplication in Fp (single)", |b| {
        b.iter_batched(
            || {
                let x: Fp = rand::random();
                let y: Fp = rand::random();
                (x, y)
            },
            |(x, y)| {
                let z: Fp = x * y;
                z
            },
            criterion::BatchSize::SmallInput,
        );
    });

    group.bench_function("Multiplication in Fp9 (single)", |b| {
        b.iter_batched(
            || {
                let x: Fp = rand::random();
                let y: Fp = rand::random();
                let x_fp9: Fp9 = x.into();
                let y_fp9: Fp9 = y.into();
                (x_fp9, y_fp9)
            },
            |(x_fp9, y_fp9)| {
                let z_fp9: Fp9 = x_fp9 * y_fp9;
                z_fp9
            },
            criterion::BatchSize::SmallInput,
        );
    });

    group.bench_function("Multiplication in Fp9 with a conversion (single)", |b| {
        b.iter_batched(
            || {
                let x: Fp = rand::random();
                let y: Fp = rand::random();
                (x, y)
            },
            |(x, y)| {
                let x_fp9: Fp9 = From::from(x);
                let y_fp9: Fp9 = From::from(y);
                let z_fp9: Fp9 = x_fp9 * y_fp9;
                z_fp9
            },
            criterion::BatchSize::SmallInput,
        );
    });

    group.bench_function("Native multiplication in Fp (double)", |b| {
        b.iter_batched(
            || {
                let x: Fp = rand::random();
                let y: Fp = rand::random();
                (x, y)
            },
            |(x, y)| {
                let z: Fp = x * y;
                let z: Fp = z * x;
                z
            },
            criterion::BatchSize::SmallInput,
        );
    });

    group.bench_function("Multiplication in Fp9 with a conversion (double)", |b| {
        b.iter_batched(
            || {
                let x: Fp = rand::random();
                let y: Fp = rand::random();
                (x, y)
            },
            |(x, y)| {
                let x_fp9: Fp9 = From::from(x);
                let y_fp9: Fp9 = From::from(y);
                let z_fp9: Fp9 = x_fp9 * y_fp9;
                let z_fp9: Fp9 = z_fp9 * x_fp9;
                z_fp9
            },
            criterion::BatchSize::SmallInput,
        );
    });

    group.bench_function("Native multiplication in Fp (4 muls)", |b| {
        b.iter_batched(
            || {
                let x: Fp = rand::random();
                let y: Fp = rand::random();
                (x, y)
            },
            |(x, y)| {
                let z: Fp = x * y;
                let z: Fp = z * x;
                let z: Fp = z * y;
                let z: Fp = z * x;
                z
            },
            criterion::BatchSize::SmallInput,
        );
    });

    group.bench_function("Multiplication in Fp9 with a conversion (4 muls)", |b| {
        b.iter_batched(
            || {
                let x: Fp = rand::random();
                let y: Fp = rand::random();
                (x, y)
            },
            |(x, y)| {
                let x_fp9: Fp9 = From::from(x);
                let y_fp9: Fp9 = From::from(y);
                let z_fp9: Fp9 = x_fp9 * y_fp9;
                let z_fp9: Fp9 = z_fp9 * x_fp9;
                let z_fp9: Fp9 = z_fp9 * y_fp9;
                let z_fp9: Fp9 = z_fp9 * x_fp9;
                z_fp9
            },
            criterion::BatchSize::SmallInput,
        );
    });
}

criterion_group!(
    benches,
    bench_poseidon_kimchi,
    bench_conversions,
    bench_basic_ops
);
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
