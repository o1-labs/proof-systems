use ark_ff::UniformRand;
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, Radix2EvaluationDomain};
use criterion::{black_box, criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};
use groupmap::GroupMap;
use mina_curves::pasta::{Fp, Vesta, VestaParameters};
use mina_poseidon::{constants::PlonkSpongeConstantsKimchi, sponge::DefaultFqSponge, FqSponge};
use poly_commitment::{
    commitment::CommitmentCurve,
    ipa::{DensePolynomialOrEvaluations, SRS},
    PolyComm, SRS as _,
};

fn benchmark_ipa_open(c: &mut Criterion) {
    let mut group = c.benchmark_group("IPA");
    let group_map = <Vesta as CommitmentCurve>::Map::setup();
    let mut rng = o1_utils::tests::make_test_rng(None);

    let elm = vec![Fp::rand(&mut rng), Fp::rand(&mut rng)];
    let polyscale = Fp::rand(&mut rng);
    let evalscale = Fp::rand(&mut rng);
    for log_n in [5, 10].into_iter() {
        let n = 1 << log_n;
        let srs = SRS::<Vesta>::create(n);
        let sponge = DefaultFqSponge::<VestaParameters, PlonkSpongeConstantsKimchi>::new(
            mina_poseidon::pasta::fq_kimchi::static_params(),
        );
        let poly_coefficients: Vec<Fp> = (0..n).map(|_| Fp::rand(&mut rng)).collect();
        let poly = DensePolynomial::<Fp>::from_coefficients_vec(poly_coefficients);
        let poly_commit = srs.commit(&poly.clone(), 1, &mut rng);
        group.bench_with_input(BenchmarkId::new("IPA Vesta open", n), &n, |b, _| {
            b.iter_batched(
                || (poly.clone(), poly_commit.clone()),
                |(poly, poly_commit)| {
                    let polys: Vec<(
                        DensePolynomialOrEvaluations<_, Radix2EvaluationDomain<_>>,
                        PolyComm<_>,
                    )> = vec![(
                        DensePolynomialOrEvaluations::DensePolynomial(&poly),
                        poly_commit.blinders,
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
                },
                BatchSize::SmallInput,
            );
        });
    }
}

criterion_group!(benches, benchmark_ipa_open);
criterion_main!(benches);
