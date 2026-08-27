//! Frozen regression benchmark for the IPA commitment-folding hot path.
//!
//! This benchmark is the pre/post measurement baseline for the fold
//! optimization series. It is intentionally minimal and **frozen**: it
//! exercises only public API (`EndoCurve::combine_one_endo` and
//! `SRS::open`), so it must keep compiling unchanged across internal
//! refactors of `combine.rs` / `ipa.rs`. Do not change what it measures;
//! later commits may touch it only to fix compile breakage.
//!
//! Cases:
//! - `combine_one_endo/{1024, 4096, 32768}` — one base-folding step
//!   (`g1[i] + g2[i].scale(endo(chal))`) at three sizes chosen to pin the
//!   shapes that matter: 32768 = round-1 multi-chunk shape (outer
//!   parallelism), 4096 = one full chunk (single-chunk rounds), 1024 =
//!   sub-chunk (pure inner-loop cost).
//! - `open/srs16` — a full `SRS::open` at SRS size 2^16, the aggregate
//!   wall-clock the series is judged on.
//!
//! Run with `cargo bench -p poly-commitment --bench fold_regression`.

use ark_ff::UniformRand;
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, Radix2EvaluationDomain};
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use groupmap::GroupMap;
use mina_curves::pasta::{Fp, Vesta, VestaParameters};
use mina_poseidon::{
    constants::PlonkSpongeConstantsKimchi,
    pasta::FULL_ROUNDS,
    sponge::{DefaultFqSponge, ScalarChallenge},
    FqSponge,
};
use poly_commitment::{
    commitment::{CommitmentCurve, EndoCurve},
    ipa::{endos, SRS},
    utils::DensePolynomialOrEvaluations,
    PolyComm, SRS as _,
};
use rand::Rng;

const SRS_LOG2: usize = 16;

fn benchmark_combine_one_endo(c: &mut Criterion) {
    let mut group = c.benchmark_group("fold_regression");
    let mut rng = o1_utils::tests::make_test_rng(Some([0u8; 32]));

    // Deterministic, production-distributed bases: SRS points are derived
    // from Blake2b, no RNG involved.
    let srs = SRS::<Vesta>::create(1 << SRS_LOG2);
    let (endo_q, endo_r) = endos::<Vesta>();

    // A fixed 128-bit endo challenge, as produced by `FqSponge::challenge`.
    let chal = ScalarChallenge::new(Fp::from(rng.gen::<u128>()));

    for n in [1024usize, 4096, 32768] {
        let g1 = &srs.g[0..n];
        let g2 = &srs.g[n..2 * n];
        group.bench_with_input(BenchmarkId::new("combine_one_endo", n), &n, |b, _| {
            b.iter(|| {
                black_box(<Vesta as EndoCurve>::combine_one_endo(
                    endo_r,
                    endo_q,
                    black_box(g1),
                    black_box(g2),
                    &chal,
                ))
            })
        });
    }
    group.finish();
}

fn benchmark_open(c: &mut Criterion) {
    let mut group = c.benchmark_group("fold_regression");
    group.sample_size(10);
    let mut rng = o1_utils::tests::make_test_rng(Some([0u8; 32]));

    let n = 1 << SRS_LOG2;
    let srs = SRS::<Vesta>::create(n);
    let group_map = <Vesta as CommitmentCurve>::Map::setup();
    let sponge = DefaultFqSponge::<VestaParameters, PlonkSpongeConstantsKimchi, FULL_ROUNDS>::new(
        mina_poseidon::pasta::fq_kimchi::static_params(),
    );

    let poly_coefficients: Vec<Fp> = (0..n).map(|_| Fp::rand(&mut rng)).collect();
    let poly = DensePolynomial::<Fp>::from_coefficients_vec(poly_coefficients);
    let poly_commit = srs.commit(&poly, 1, &mut rng);

    let elm = vec![Fp::rand(&mut rng), Fp::rand(&mut rng)];
    let polyscale = Fp::rand(&mut rng);
    let evalscale = Fp::rand(&mut rng);

    group.bench_function("open/srs16", |b| {
        b.iter(|| {
            let polys: Vec<(
                DensePolynomialOrEvaluations<_, Radix2EvaluationDomain<_>>,
                PolyComm<_>,
            )> = vec![(
                DensePolynomialOrEvaluations::DensePolynomial(&poly),
                poly_commit.blinders.clone(),
            )];
            black_box(srs.open(
                &group_map,
                &polys,
                &elm,
                polyscale,
                evalscale,
                sponge.clone(),
                &mut rng,
            ))
        })
    });
    group.finish();
}

criterion_group!(benches, benchmark_combine_one_endo, benchmark_open);
criterion_main!(benches);
