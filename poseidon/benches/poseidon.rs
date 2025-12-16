use mina_poseidon::{
    constants::{PlonkSpongeConstantsKimchi, PlonkSpongeConstantsLegacy},
    pasta::{
        fp_kimchi as SpongeParametersKimchi, fp_legacy as SpongeParametersLegacy, FULL_ROUNDS,
    },
    permutation::poseidon_block_cipher,
};
use rand::{rngs::StdRng, thread_rng, Rng, SeedableRng};

use ark_ff::UniformRand;
use criterion::{criterion_group, criterion_main, Criterion};
use mina_curves::pasta::Fp;

pub fn bench_poseidon_absorb_permutation_pasta_fp(c: &mut Criterion) {
    // FIXME: use o1_utils test rng
    let seed = thread_rng().gen();
    eprintln!("Seed: {seed:?}");
    let mut rng = StdRng::from_seed(seed);

    let input: [Fp; 3] = std::array::from_fn(|_| Fp::rand(&mut rng));
    let mut input: Vec<Fp> = Vec::from(input);

    let params = SpongeParametersKimchi::static_params();
    c.bench_function("poseidon_absorb_permutation kimchi", |b| {
        b.iter(|| {
            poseidon_block_cipher::<Fp, PlonkSpongeConstantsKimchi, FULL_ROUNDS>(
                params, &mut input,
            );
        })
    });

    let params = SpongeParametersLegacy::static_params();
    c.bench_function("poseidon_absorb_permutation legacy", |b| {
        b.iter(|| {
            poseidon_block_cipher::<Fp, PlonkSpongeConstantsLegacy, 100>(params, &mut input);
        })
    });
}

criterion_group!(benches, bench_poseidon_absorb_permutation_pasta_fp);
criterion_main!(benches);
