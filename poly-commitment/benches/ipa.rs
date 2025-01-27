use ark_ff::UniformRand;
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, Radix2EvaluationDomain};
use criterion::{black_box, criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};
use groupmap::GroupMap;
use mina_curves::pasta::{Fp, Vesta, VestaParameters};
use mina_poseidon::{constants::PlonkSpongeConstantsKimchi, sponge::DefaultFqSponge, FqSponge};
use poly_commitment::{
    commitment::CommitmentCurve, ipa::SRS, utils::DensePolynomialOrEvaluations, PolyComm, SRS as _,
};

fn benchmark_msm(c: &mut Criterion) {
    use ark_ec::{AffineRepr, VariableBaseMSM};
    use ark_ff::PrimeField;

    let mut group = c.benchmark_group("MSM");
    let mut rng = o1_utils::tests::make_test_rng(None);

    let srs = SRS::<Vesta>::create(1 << 16);
    srs.get_lagrange_basis_from_domain_size(1 << 16);

    for msm_size_log in [8, 10, 12, 14, 16].into_iter() {
        let n = 1 << msm_size_log;
        group.bench_function(format!("msm (size 2^{{{}}})", msm_size_log), |b| {
            b.iter_batched(
                || {
                    let coeffs: Vec<Fp> = (0..n).map(|_| Fp::rand(&mut rng)).collect();
                    coeffs
                },
                |coeffs| black_box(<Vesta as AffineRepr>::Group::msm(&srs.g[0..n], &coeffs)),
                BatchSize::LargeInput,
            )
        });
        group.bench_function(format!("msm bigint (size 2^{{{}}})", msm_size_log), |b| {
            b.iter_batched(
                || {
                    let coeffs: Vec<Fp> = (0..n).map(|_| Fp::rand(&mut rng)).collect();
                    let coeffs_bigint: Vec<_> =
                        coeffs.into_iter().map(|c| c.into_bigint()).collect();
                    coeffs_bigint
                },
                |coeffs_bigint| {
                    black_box(<Vesta as AffineRepr>::Group::msm_bigint(
                        &srs.g,
                        &coeffs_bigint,
                    ))
                },
                BatchSize::LargeInput,
            )
        });
        group.bench_function(
            format!("msm bigint + conversion (size 2^{{{}}})", msm_size_log),
            |b| {
                b.iter_batched(
                    || {
                        let coeffs: Vec<Fp> = (0..n).map(|_| Fp::rand(&mut rng)).collect();
                        coeffs
                    },
                    |coeffs| {
                        black_box(<Vesta as AffineRepr>::Group::msm_bigint(
                            &srs.g,
                            &coeffs
                                .into_iter()
                                .map(|c| c.into_bigint())
                                .collect::<Vec<_>>(),
                        ))
                    },
                    BatchSize::LargeInput,
                )
            },
        );
    }
}

fn benchmark_ipa_commit(c: &mut Criterion) {
    let mut group = c.benchmark_group("IPA Commit");
    let mut rng = o1_utils::tests::make_test_rng(None);

    for srs_size_log in [8, 12, 16].into_iter() {
        let n = 1 << srs_size_log;
        let srs = SRS::<Vesta>::create(n);
        srs.get_lagrange_basis_from_domain_size(n);

        for chunks_n in [1usize, 2, 4, 8].into_iter() {
            group.bench_function(
                format!(
                    "commitment (SRS size 2^{{{}}}, {} chunks)",
                    srs_size_log, chunks_n
                ),
                |b| {
                    b.iter_batched(
                        || {
                            let poly_coefficients: Vec<Fp> =
                                (0..chunks_n * n).map(|_| Fp::rand(&mut rng)).collect();
                            DensePolynomial::<Fp>::from_coefficients_vec(poly_coefficients)
                        },
                        |poly| black_box(srs.commit_non_hiding(&poly, chunks_n)),
                        BatchSize::LargeInput,
                    )
                },
            );
        }
    }
}

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

criterion_group!(
    benches,
    benchmark_msm,
    benchmark_ipa_commit,
    benchmark_ipa_open
);
criterion_main!(benches);
